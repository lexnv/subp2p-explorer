// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use crate::commands::authorities::{
    fetch_genesis_hash, fetch_ss58_prefix, resolve_bootnodes, runtime_api_autorities,
    AuthorityDiscovery,
};
use crate::utils::{build_swarm, is_public_address};
use futures::StreamExt;
use jsonrpsee::client_transport::ws::Url;
use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
use std::collections::HashMap;
use std::error::Error;
use std::time::{Duration, Instant};
use subp2p_explorer::util::p2p::get_peer_id;
use subp2p_explorer::util::ss58::to_ss58;
use tokio::net::TcpStream;

/// Maximum number of concurrent TCP connection checks.
const MAX_PARALLEL_CHECKS: usize = 64;

/// Result of checking a single address.
enum AddressResult {
    /// TCP connection succeeded.
    Ok,
    /// TCP connection failed.
    Failed(String),
    /// Check was skipped.
    Skipped(String),
}

/// Address check details for a single multiaddress.
struct AddressCheck {
    address_short: String,
    is_public: bool,
    result: AddressResult,
}

/// Aggregated result of checking a single authority.
struct AuthorityResult {
    authority_ss58: String,
    peer_id: Option<PeerId>,
    agent_version: Option<String>,
    has_dht_record: bool,
    addresses: Vec<AddressCheck>,
}

/// Global statistics computed from all authority results.
struct GlobalStats {
    total_authorities: usize,
    with_dht_records: usize,
    with_peer_id: usize,
    identified: usize,
    total_addresses: usize,
    public_addresses: usize,
    private_addresses: usize,
    reachable_public: usize,
    unreachable_public: usize,
    reachable_authorities: usize,
    fully_reachable_authorities: usize,
    agent_versions: HashMap<String, usize>,
}

/// Remove the `/p2p/<peer_id>` suffix from a multiaddress for compact display.
fn shorten_address(addr: &Multiaddr) -> String {
    let s = addr.to_string();
    if let Some(idx) = s.rfind("/p2p/") {
        s[..idx].to_string()
    } else {
        s
    }
}

/// Extract `host:port` from a multiaddress for TCP connection checking.
///
/// Supports `/ip4/`, `/ip6/`, `/dns/`, `/dns4/`, `/dns6/` followed by `/tcp/<port>`.
fn extract_tcp_endpoint(addr: &Multiaddr) -> Option<String> {
    let mut iter = addr.iter();
    let host = match iter.next()? {
        Protocol::Ip4(ip) => ip.to_string(),
        Protocol::Ip6(ip) => format!("[{}]", ip),
        Protocol::Dns(host) | Protocol::Dns4(host) | Protocol::Dns6(host) => host.to_string(),
        _ => return None,
    };
    match iter.next()? {
        Protocol::Tcp(port) => Some(format!("{}:{}", host, port)),
        _ => None,
    }
}

/// Check if a TCP endpoint is reachable within the given timeout.
async fn check_tcp_reachable(endpoint: &str, timeout: Duration) -> Result<(), String> {
    match tokio::time::timeout(timeout, TcpStream::connect(endpoint)).await {
        Ok(Ok(_stream)) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("timeout".to_string()),
    }
}

/// Run TCP connectivity checks for all addresses concurrently.
///
/// Each entry in `checks` is `(authority_index, multiaddr, is_public)`.
/// Returns results grouped by authority index.
async fn run_connectivity_checks(
    checks: Vec<(usize, Multiaddr, bool)>,
    dial_timeout: Duration,
) -> HashMap<usize, Vec<AddressCheck>> {
    let total = checks.len();
    let public_count = checks.iter().filter(|(_, _, p)| *p).count();
    let start = Instant::now();

    let results: Vec<(usize, AddressCheck)> = futures::stream::iter(checks)
        .map(|(idx, addr, is_public)| async move {
            let address_short = shorten_address(&addr);

            let result = if !is_public {
                AddressResult::Skipped("private".into())
            } else if let Some(endpoint) = extract_tcp_endpoint(&addr) {
                match check_tcp_reachable(&endpoint, dial_timeout).await {
                    Ok(()) => AddressResult::Ok,
                    Err(e) => AddressResult::Failed(e),
                }
            } else {
                AddressResult::Skipped("unsupported transport".into())
            };

            (
                idx,
                AddressCheck {
                    address_short,
                    is_public,
                    result,
                },
            )
        })
        .buffer_unordered(MAX_PARALLEL_CHECKS)
        .collect()
        .await;

    let elapsed = start.elapsed();
    println!(
        "       Checked {} addresses ({} public) in {:.1}s",
        total,
        public_count,
        elapsed.as_secs_f64()
    );

    let mut grouped: HashMap<usize, Vec<AddressCheck>> = HashMap::new();
    for (idx, check) in results {
        grouped.entry(idx).or_default().push(check);
    }
    grouped
}

/// Print the per-authority check result in a formatted table.
fn print_authority_result(result: &AuthorityResult, index: usize) {
    println!("────────────────────────────────────────────────────────────────────────");
    print!("  Authority #{}: {}", index + 1, result.authority_ss58);

    if !result.has_dht_record {
        println!(" — No DHT record");
        return;
    }
    println!();

    if let Some(ref peer_id) = result.peer_id {
        println!("  PeerId: {}", peer_id);
    }
    if let Some(ref agent) = result.agent_version {
        println!("  Agent:  {}", agent);
    }

    if result.addresses.is_empty() {
        println!("  No addresses in DHT record");
        return;
    }

    println!();

    let max_len = result
        .addresses
        .iter()
        .map(|a| a.address_short.len())
        .max()
        .unwrap_or(30)
        .min(65);

    for check in &result.addresses {
        let addr = if check.address_short.len() > max_len {
            format!("{}...", &check.address_short[..max_len - 3])
        } else {
            format!("{:<width$}", check.address_short, width = max_len)
        };

        let kind = if check.is_public {
            "public "
        } else {
            "private"
        };

        let status = match &check.result {
            AddressResult::Ok => "\x1b[32mOK\x1b[0m".to_string(),
            AddressResult::Failed(e) => format!("\x1b[31mFAIL\x1b[0m ({})", e),
            AddressResult::Skipped(r) => format!("\x1b[33mSKIP\x1b[0m ({})", r),
        };

        println!("    {} | {} | {}", addr, kind, status);
    }

    let total = result.addresses.len();
    let public = result.addresses.iter().filter(|a| a.is_public).count();
    let private = total - public;
    let reachable = result
        .addresses
        .iter()
        .filter(|a| matches!(a.result, AddressResult::Ok))
        .count();
    let public_tested = result
        .addresses
        .iter()
        .filter(|a| a.is_public && !matches!(a.result, AddressResult::Skipped(_)))
        .count();

    let pct = if public_tested > 0 {
        format!("{:.1}%", reachable as f64 / public_tested as f64 * 100.0)
    } else {
        "N/A".to_string()
    };

    println!();
    println!(
        "    Reachable: {}/{} public ({}) | Total: {} addrs ({} public, {} private)",
        reachable, public_tested, pct, total, public, private
    );
}

/// Normalize an agent version string for aggregation.
///
/// Strips the commit hash and node-specific name, keeping only the base version
/// and backend indicator. For example:
///   "Parity Polkadot/v1.21.1-c6ba84fb493 (mynode) (litep2p)" → "Parity Polkadot/v1.21.1 (litep2p)"
fn normalize_agent_version(version: &str) -> String {
    if let Some(v_pos) = version.find("/v") {
        let after_v = &version[v_pos + 2..];
        let end = after_v
            .find('-')
            .or_else(|| after_v.find(' '))
            .unwrap_or(after_v.len());
        let base = &version[..v_pos + 2 + end];

        let backend = if version.contains("(litep2p)") {
            " (litep2p)"
        } else {
            ""
        };

        format!("{}{}", base, backend)
    } else {
        version.to_string()
    }
}

/// Compute global statistics from all authority results.
fn compute_global_stats(results: &[AuthorityResult]) -> GlobalStats {
    let mut stats = GlobalStats {
        total_authorities: results.len(),
        with_dht_records: 0,
        with_peer_id: 0,
        identified: 0,
        total_addresses: 0,
        public_addresses: 0,
        private_addresses: 0,
        reachable_public: 0,
        unreachable_public: 0,
        reachable_authorities: 0,
        fully_reachable_authorities: 0,
        agent_versions: HashMap::new(),
    };

    for r in results {
        if r.has_dht_record {
            stats.with_dht_records += 1;
        }
        if r.peer_id.is_some() {
            stats.with_peer_id += 1;
        }
        if let Some(ref v) = r.agent_version {
            stats.identified += 1;
            let normalized = normalize_agent_version(v);
            *stats.agent_versions.entry(normalized).or_insert(0) += 1;
        }

        let any_ok = r
            .addresses
            .iter()
            .any(|a| matches!(a.result, AddressResult::Ok));
        if any_ok {
            stats.reachable_authorities += 1;
        }

        let pub_tested: Vec<_> = r
            .addresses
            .iter()
            .filter(|a| a.is_public && !matches!(a.result, AddressResult::Skipped(_)))
            .collect();
        let all_pub_ok = !pub_tested.is_empty()
            && pub_tested
                .iter()
                .all(|a| matches!(a.result, AddressResult::Ok));
        if all_pub_ok {
            stats.fully_reachable_authorities += 1;
        }

        for a in &r.addresses {
            stats.total_addresses += 1;
            if a.is_public {
                stats.public_addresses += 1;
                match &a.result {
                    AddressResult::Ok => stats.reachable_public += 1,
                    AddressResult::Failed(_) => stats.unreachable_public += 1,
                    AddressResult::Skipped(_) => {}
                }
            } else {
                stats.private_addresses += 1;
            }
        }
    }

    stats
}

/// Print the global summary with formatted statistics.
fn print_global_summary(stats: &GlobalStats) {
    let pct = |n: usize, d: usize| -> String {
        if d > 0 {
            format!("{:.1}%", n as f64 / d as f64 * 100.0)
        } else {
            "N/A".to_string()
        }
    };

    println!();
    println!("════════════════════════════════════════════════════════════════════════");
    println!("                          GLOBAL SUMMARY");
    println!("════════════════════════════════════════════════════════════════════════");
    println!();

    println!("  Authorities");
    println!(
        "  ├─ Total (runtime API):          {:>6}",
        stats.total_authorities
    );
    println!(
        "  ├─ With DHT records:             {:>6} ({})",
        stats.with_dht_records,
        pct(stats.with_dht_records, stats.total_authorities)
    );
    println!(
        "  ├─ With Peer ID:                 {:>6} ({})",
        stats.with_peer_id,
        pct(stats.with_peer_id, stats.total_authorities)
    );
    println!(
        "  └─ Identified (p2p):             {:>6} ({})",
        stats.identified,
        pct(stats.identified, stats.total_authorities)
    );
    println!();

    println!("  Addresses");
    println!(
        "  ├─ Total:                        {:>6}",
        stats.total_addresses
    );
    println!(
        "  ├─ Public:                       {:>6} ({})",
        stats.public_addresses,
        pct(stats.public_addresses, stats.total_addresses)
    );
    println!(
        "  └─ Private:                      {:>6} ({})",
        stats.private_addresses,
        pct(stats.private_addresses, stats.total_addresses)
    );
    println!();

    println!("  Connectivity");
    println!(
        "  ├─ Reachable authorities (>=1):  {:>6} ({})",
        stats.reachable_authorities,
        pct(stats.reachable_authorities, stats.total_authorities)
    );
    println!(
        "  ├─ Fully reachable (all public): {:>6} ({})",
        stats.fully_reachable_authorities,
        pct(stats.fully_reachable_authorities, stats.total_authorities)
    );
    println!(
        "  ├─ Public addrs reachable:  {:>6}/{:<6} ({})",
        stats.reachable_public,
        stats.public_addresses,
        pct(stats.reachable_public, stats.public_addresses)
    );
    println!(
        "  └─ Public addrs unreachable:{:>6}/{:<6} ({})",
        stats.unreachable_public,
        stats.public_addresses,
        pct(stats.unreachable_public, stats.public_addresses)
    );

    if !stats.agent_versions.is_empty() {
        println!();
        println!("  Agent Distribution");
        let mut versions: Vec<_> = stats.agent_versions.iter().collect();
        versions.sort_by(|a, b| b.1.cmp(a.1));
        let len = versions.len();
        for (i, (version, count)) in versions.iter().enumerate() {
            let branch = if i == len - 1 { "└─" } else { "├─" };
            let v = if version.len() > 40 {
                format!("{}...", &version[..37])
            } else {
                version.to_string()
            };
            println!("  {} {:<42} {:>4}", branch, v, count);
        }
    }

    println!();
}

/// Entry function for the `authority-check` CLI command.
///
/// Discovers authorities via the runtime API, scrapes their DHT records
/// to collect advertised multiaddresses, then checks TCP connectivity
/// to each address. Prints per-authority results and global statistics.
pub async fn check_authorities(
    url: String,
    genesis: Option<String>,
    bootnodes: Vec<String>,
    timeout: Duration,
    dial_timeout: Duration,
    address_format: Option<String>,
    query_timeout: Duration,
) -> Result<(), Box<dyn Error>> {
    println!("════════════════════════════════════════════════════════════════════════");
    println!("                         AUTHORITY CHECK");
    println!("════════════════════════════════════════════════════════════════════════");
    println!();

    let rpc_url = Url::parse(&url)?;

    // Resolve SS58 prefix: use provided format name or fetch from RPC.
    let version = match address_format {
        Some(fmt) => {
            let format_registry =
                ss58_registry::Ss58AddressFormatRegistry::try_from(fmt.as_str())
                    .map_err(|err| {
                        format!("Cannot parse the provided address format: {:?}", err)
                    })?;
            let v: ss58_registry::Ss58AddressFormat = format_registry.into();
            v.prefix()
        }
        None => {
            println!("       No address format provided, fetching from RPC...");
            let prefix = fetch_ss58_prefix(rpc_url.clone()).await?;
            let name = ss58_registry::Ss58AddressFormatRegistry::try_from(
                ss58_registry::Ss58AddressFormat::custom(prefix),
            );
            match name {
                Ok(registry) => println!("       Address format: {:?} (prefix: {})", registry, prefix),
                Err(_) => println!("       SS58 prefix: {}", prefix),
            }
            println!();
            prefix
        }
    };

    // Resolve genesis hash: use provided one or fetch from RPC.
    let genesis = match genesis {
        Some(g) => g,
        None => {
            println!("       No genesis hash provided, fetching from RPC...");
            let hash = fetch_genesis_hash(rpc_url.clone()).await?;
            println!("       Genesis hash: 0x{}", hash);
            println!();
            hash
        }
    };

    // Resolve bootnodes: use provided ones, fetch from RPC, and merge with published chainspec.
    let bootnodes = resolve_bootnodes(&rpc_url, bootnodes).await?;

    // Phase 1: Fetch authorities from the runtime API.
    println!("[1/3] Fetching authorities from runtime API...");
    let authorities = runtime_api_autorities(rpc_url).await?;
    println!("       Found {} authorities", authorities.len());
    println!();

    // Phase 2: DHT Discovery — scrape authority records for addresses and peer IDs.
    println!(
        "[2/3] Discovering authority DHT records (timeout: {}s)...",
        timeout.as_secs()
    );
    let swarm = build_swarm(genesis, bootnodes, query_timeout).await?;
    let mut discovery = AuthorityDiscovery::new(swarm, authorities.clone(), timeout);
    discovery.set_show_progress(true);
    discovery.discover().await;

    let dht_count = discovery.authority_to_details().len();
    let identified_count = discovery.peer_info().len();
    println!(
        "       DHT records: {}/{} | Identified peers: {}",
        dht_count,
        authorities.len(),
        identified_count
    );
    println!();

    // Phase 3: TCP connectivity checks on every discovered address.
    let mut pending_checks: Vec<(usize, Multiaddr, bool)> = Vec::new();
    for (idx, authority) in authorities.iter().enumerate() {
        if let Some(addrs) = discovery.authority_to_details().get(authority) {
            for addr in addrs {
                let is_pub = is_public_address(addr);
                pending_checks.push((idx, addr.clone(), is_pub));
            }
        }
    }

    let public_count = pending_checks.iter().filter(|(_, _, p)| *p).count();
    println!(
        "[3/3] Checking connectivity ({} addresses, {} public, timeout: {}s/addr)...",
        pending_checks.len(),
        public_count,
        dial_timeout.as_secs()
    );

    let mut check_results = run_connectivity_checks(pending_checks, dial_timeout).await;
    println!();

    // Build per-authority results.
    let mut results: Vec<AuthorityResult> = Vec::with_capacity(authorities.len());

    for (idx, authority) in authorities.iter().enumerate() {
        let authority_ss58 = to_ss58(authority, version);

        let Some(addrs) = discovery.authority_to_details().get(authority) else {
            results.push(AuthorityResult {
                authority_ss58,
                peer_id: None,
                agent_version: None,
                has_dht_record: false,
                addresses: Vec::new(),
            });
            continue;
        };

        let peer_id = addrs.iter().find_map(get_peer_id);
        let agent_version = peer_id
            .and_then(|pid| discovery.peer_info().get(&pid))
            .map(|info| info.agent_version.clone());
        let addresses = check_results.remove(&idx).unwrap_or_default();

        results.push(AuthorityResult {
            authority_ss58,
            peer_id,
            agent_version,
            has_dht_record: true,
            addresses,
        });
    }

    // Print per-authority details.
    for (i, result) in results.iter().enumerate() {
        print_authority_result(result, i);
    }

    // Print global summary.
    let stats = compute_global_stats(&results);
    print_global_summary(&stats);

    Ok(())
}
