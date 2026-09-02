// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use crate::commands::authorities::{
    detect_chain_name, fetch_genesis_hash, fetch_ss58_prefix, resolve_bootnodes,
    runtime_api_autorities, AuthorityDiscovery, DialOutcome,
};
use crate::commands::authority_check_litep2p::Litep2pAuthorityDiscovery;
use crate::commands::identity::{fetch_identity_names, IdentityResult};
use crate::utils::{build_swarm, is_public_address};
use futures::StreamExt;
use jsonrpsee::client_transport::ws::Url;
use libp2p::{identify::Info, multiaddr::Protocol, Multiaddr, PeerId};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use subp2p_explorer::util::crypto::sr25519;
use subp2p_explorer::util::p2p::get_peer_id;
use subp2p_explorer::util::ss58::to_ss58;
use tokio::net::TcpStream;

/// Maximum number of concurrent TCP connection checks.
///
/// Bounded so that the file descriptors stay well below common `ulimit -n`
/// values even on large networks (e.g. Kusama with 1000+ validators). At 64
/// the check dominated the wall time: unreachable addresses hold their slot
/// for the full dial timeout, and batches complete at the pace of their
/// slowest member.
const MAX_PARALLEL_CHECKS: usize = 256;

/// Network stack used to crawl the DHT and probe the authorities.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum NetworkBackend {
    /// The rust-libp2p stack.
    #[default]
    Libp2p,
    /// The litep2p stack.
    Litep2p,
}

impl NetworkBackend {
    /// Lower-case name, as used in file names and in the JSON report.
    pub fn name(self) -> &'static str {
        match self {
            NetworkBackend::Libp2p => "libp2p",
            NetworkBackend::Litep2p => "litep2p",
        }
    }

    /// Capitalized name, for the report headings.
    fn title(self) -> &'static str {
        match self {
            NetworkBackend::Libp2p => "Libp2p",
            NetworkBackend::Litep2p => "Litep2p",
        }
    }
}

/// The parts of an identify response used by the report, in a form produced
/// by both network backends.
pub struct IdentifyInfo {
    /// Name and version of the peer, e.g. `Parity Polkadot/v1.21.1-... (litep2p)`.
    pub agent_version: String,
    /// The addresses the peer claims to listen on.
    pub listen_addrs: Vec<Multiaddr>,
}

impl From<Info> for IdentifyInfo {
    fn from(info: Info) -> Self {
        IdentifyInfo {
            agent_version: info.agent_version,
            listen_addrs: info.listen_addrs,
        }
    }
}

/// What a crawl hands back to the report, for both network backends: the
/// addresses found in the DHT record of each authority, the identify response
/// of every peer reached, the outcome of every dial, and every peer a
/// connection was established with.
pub type DiscoveryResults = (
    HashMap<sr25519::PublicKey, HashSet<Multiaddr>>,
    HashMap<PeerId, IdentifyInfo>,
    HashMap<Multiaddr, DialOutcome>,
    HashSet<PeerId>,
);

/// Writer that duplicates output to stdout and an optional log file.
struct DualWriter {
    file: Option<BufWriter<File>>,
}

impl DualWriter {
    fn new(file: Option<File>) -> Self {
        DualWriter {
            file: file.map(BufWriter::new),
        }
    }
}

/// Strip ANSI escape sequences (`\x1b[...m`) from a byte slice.
fn strip_ansi(buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(buf.len());
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == b'\x1b' && buf.get(i + 1) == Some(&b'[') {
            // Skip past the closing 'm'.
            i += 2;
            while i < buf.len() && buf[i] != b'm' {
                i += 1;
            }
            if i < buf.len() {
                i += 1; // skip 'm'
            }
        } else {
            out.push(buf[i]);
            i += 1;
        }
    }
    out
}

impl Write for DualWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::stdout().write_all(buf)?;
        if let Some(ref mut f) = self.file {
            f.write_all(&strip_ansi(buf))?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()?;
        if let Some(ref mut f) = self.file {
            f.flush()?;
        }
        Ok(())
    }
}

/// Result of checking a single address.
#[derive(Serialize)]
#[serde(tag = "status", content = "reason")]
enum AddressResult {
    /// TCP connection succeeded.
    Ok,
    /// TCP connection failed.
    Failed(String),
    /// Check was skipped.
    Skipped(String),
}

/// Address check details for a single multiaddress.
#[derive(Serialize)]
struct AddressCheck {
    address_short: String,
    is_public: bool,
    result: AddressResult,
    /// Outcome of the p2p dial (noise + yamux).
    #[serde(skip_serializing_if = "Option::is_none")]
    dial_outcome: Option<DialOutcome>,
    /// Full multiaddress (not serialized, used for dial outcome lookup).
    #[serde(skip_serializing)]
    full_address: Option<Multiaddr>,
}

/// Aggregated result of checking a single authority.
#[derive(Serialize)]
struct AuthorityResult {
    authority_ss58: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    stash_ss58: Option<String>,
    identity_name: Option<String>,
    peer_id: Option<String>,
    agent_version: Option<String>,
    has_dht_record: bool,
    /// Addresses the peer reported about itself over the identify protocol.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    identify_addresses: Vec<String>,
    /// Transports found across all known addresses (DHT record + identify).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    transports: Vec<&'static str>,
    addresses: Vec<AddressCheck>,
}

/// Number of validators advertising each transport, across DHT record and
/// identify addresses. A validator listening on several transports is counted
/// once per transport.
#[derive(Serialize, Default)]
struct TransportStats {
    tcp: usize,
    websocket: usize,
    webrtc: usize,
    quic: usize,
}

/// Global statistics computed from all authority results.
#[derive(Serialize)]
struct GlobalStats {
    total_authorities: usize,
    with_identity: usize,
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
    /// Authorities we established at least one p2p connection with, through
    /// whichever network backend ran the crawl. The key is kept for
    /// compatibility with older reports.
    libp2p_reachable_authorities: usize,
    /// Number of public addresses where the p2p dial succeeded.
    dial_success: usize,
    /// Number of public addresses where the p2p dial failed.
    dial_failed: usize,
    /// Number of public addresses that were not dialed, mostly because the peer
    /// was already connected through another address.
    dial_skipped: usize,
    /// Number of public addresses with no dial outcome (never attempted).
    dial_pending: usize,
    /// Per-transport validator counts (TCP, WebSocket, WebRTC, QUIC).
    transports: TransportStats,
}

/// Statistics over every node reached while crawling the DHT, not just the
/// validators. Kademlia connects to many regular network nodes on the way to
/// the authority records, and each identify response reveals the transports
/// that node runs.
#[derive(Serialize)]
struct AllNodesStats {
    /// Distinct peers a connection was established with during the crawl.
    reached_peers: usize,
    /// Reached peers that answered the identify protocol.
    identified: usize,
    /// Identified peers that belong to the current authority set.
    validators: usize,
    /// Identified peers outside the authority set.
    non_validators: usize,
    /// Per-transport node counts from identify listen addresses. A node
    /// listening on several transports is counted once per transport.
    transports: TransportStats,
    /// Identified peers whose listen addresses matched no known transport.
    no_known_transport: usize,
    /// Agent version distribution across all identified peers.
    agent_versions: HashMap<String, usize>,
}

/// Top-level JSON report containing all authority results and global statistics.
#[derive(Serialize)]
struct JsonReport<'a> {
    chain: Option<&'static str>,
    rpc_url: &'a str,
    /// Network stack that ran the crawl.
    network_backend: NetworkBackend,
    authorities: &'a [AuthorityResult],
    stats: &'a GlobalStats,
    /// Statistics over every node reached during the crawl (validators and
    /// regular network nodes alike).
    all_nodes: &'a AllNodesStats,
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

/// Classify the transport of a multiaddress.
///
/// WebSocket addresses also carry a `/tcp` component, so the more specific
/// protocols are matched before falling back to plain TCP.
fn classify_transport(addr: &Multiaddr) -> Option<&'static str> {
    let mut tcp = false;
    for proto in addr.iter() {
        match proto {
            Protocol::Ws(_) | Protocol::Wss(_) => return Some("websocket"),
            Protocol::WebRTC | Protocol::WebRTCDirect => return Some("webrtc"),
            Protocol::Quic | Protocol::QuicV1 => return Some("quic"),
            Protocol::Tcp(_) => tcp = true,
            _ => (),
        }
    }
    tcp.then_some("tcp")
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

/// Run TCP connectivity checks for all addresses in batches.
///
/// Each entry in `checks` is `(authority_index, multiaddr, is_public)`.
/// Returns results grouped by authority index.
///
/// Addresses are processed in batches of [`MAX_PARALLEL_CHECKS`] so that
/// file descriptors from one batch are fully released before the next batch
/// begins. This prevents "too many open files" errors on large networks
/// (e.g. Kusama with 1000+ validators).
async fn run_connectivity_checks(
    mut checks: Vec<(usize, Multiaddr, bool)>,
    dial_timeout: Duration,
    w: &mut DualWriter,
) -> HashMap<usize, Vec<AddressCheck>> {
    let total = checks.len();
    let public_count = checks.iter().filter(|(_, _, p)| *p).count();
    let start = Instant::now();

    let mut grouped: HashMap<usize, Vec<AddressCheck>> = HashMap::new();
    let mut checked = 0usize;

    while !checks.is_empty() {
        let batch_end = checks.len().min(MAX_PARALLEL_CHECKS);
        let batch: Vec<_> = checks.drain(..batch_end).collect();

        let batch_results: Vec<(usize, AddressCheck)> = futures::stream::iter(batch)
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
                        dial_outcome: None,
                        full_address: Some(addr),
                    },
                )
            })
            .buffer_unordered(MAX_PARALLEL_CHECKS)
            .collect()
            .await;

        checked += batch_results.len();
        for (idx, check) in batch_results {
            grouped.entry(idx).or_default().push(check);
        }

        let _ = write!(w, "\r       Checked {}/{} addresses ...", checked, total,);
        let _ = w.flush();
    }

    let elapsed = start.elapsed();
    let _ = writeln!(
        w,
        "\r       Checked {} addresses ({} public) in {:.1}s                ",
        total,
        public_count,
        elapsed.as_secs_f64()
    );

    grouped
}

/// An authority is considered failing when it has no DHT record, has no public
/// addresses, or at least one public address is unreachable.
fn is_authority_failing(result: &AuthorityResult) -> bool {
    if !result.has_dht_record {
        return true;
    }

    let public: Vec<_> = result
        .addresses
        .iter()
        .filter(|a| a.is_public && !matches!(a.result, AddressResult::Skipped(_)))
        .collect();

    if public.is_empty() {
        return true;
    }

    public
        .iter()
        .any(|a| matches!(a.result, AddressResult::Failed(_)))
}

/// Print the per-authority check result in a formatted table.
fn print_authority_result(
    w: &mut DualWriter,
    result: &AuthorityResult,
    index: usize,
) -> io::Result<()> {
    writeln!(
        w,
        "────────────────────────────────────────────────────────────────────────"
    )?;
    write!(w, "  Authority #{}: {}", index + 1, result.authority_ss58)?;

    if !result.has_dht_record {
        writeln!(w, " — No DHT record")?;
        return Ok(());
    }
    writeln!(w)?;

    if let Some(ref stash) = result.stash_ss58 {
        writeln!(w, "  Stash:    {}", stash)?;
    }
    if let Some(ref name) = result.identity_name {
        writeln!(w, "  Identity: {}", name)?;
    }
    if let Some(ref peer_id) = result.peer_id {
        writeln!(w, "  PeerId:   {}", peer_id)?;
    }
    if let Some(ref agent) = result.agent_version {
        writeln!(w, "  Agent:    {}", agent)?;
    }
    if !result.transports.is_empty() {
        writeln!(w, "  Transports: {}", result.transports.join(", "))?;
    }

    if !result.identify_addresses.is_empty() {
        writeln!(w)?;
        writeln!(w, "  Identify addresses:")?;
        for addr in &result.identify_addresses {
            writeln!(w, "    {}", addr)?;
        }
    }

    if result.addresses.is_empty() {
        writeln!(w, "  No addresses in DHT record")?;
        return Ok(());
    }

    writeln!(w)?;

    let max_len = result
        .addresses
        .iter()
        .map(|a| a.address_short.len())
        .max()
        .unwrap_or(30);

    for check in &result.addresses {
        let addr = format!("{:<width$}", check.address_short, width = max_len);

        let kind = if check.is_public {
            "public "
        } else {
            "private"
        };

        let dial_status = match &check.dial_outcome {
            Some(DialOutcome::Success) => "\x1b[32mOK\x1b[0m".to_string(),
            Some(DialOutcome::Failed(e)) => format!("\x1b[31mFAIL\x1b[0m ({})", e),
            Some(DialOutcome::Skipped(r)) => format!("\x1b[33mSKIP\x1b[0m ({})", r),
            None => "\x1b[33m-\x1b[0m".to_string(),
        };

        let tcp_status = match &check.result {
            AddressResult::Ok => "\x1b[32mOK\x1b[0m".to_string(),
            AddressResult::Failed(e) => format!("\x1b[31mFAIL\x1b[0m ({})", e),
            AddressResult::Skipped(r) => format!("\x1b[33mSKIP\x1b[0m ({})", r),
        };

        writeln!(
            w,
            "    {} | {} | Dial: {} | TCP: {}",
            addr, kind, dial_status, tcp_status
        )?;
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

    writeln!(w)?;
    writeln!(
        w,
        "    Reachable: {}/{} public ({}) | Total: {} addrs ({} public, {} private)",
        reachable, public_tested, pct, total, public, private
    )?;
    Ok(())
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
        with_identity: 0,
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
        libp2p_reachable_authorities: 0,
        agent_versions: HashMap::new(),
        dial_success: 0,
        dial_failed: 0,
        dial_skipped: 0,
        dial_pending: 0,
        transports: TransportStats::default(),
    };

    for r in results {
        if r.identity_name.is_some() {
            stats.with_identity += 1;
        }
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

        for transport in &r.transports {
            match *transport {
                "tcp" => stats.transports.tcp += 1,
                "websocket" => stats.transports.websocket += 1,
                "webrtc" => stats.transports.webrtc += 1,
                "quic" => stats.transports.quic += 1,
                _ => (),
            }
        }

        let any_ok = r
            .addresses
            .iter()
            .any(|a| matches!(a.result, AddressResult::Ok));
        if any_ok {
            stats.reachable_authorities += 1;
        }

        // An identified peer was necessarily connected, even when the
        // connection was opened by Kademlia on an address we never probed
        // ourselves.
        let libp2p_ok = r.agent_version.is_some()
            || r.addresses
                .iter()
                .any(|a| matches!(a.dial_outcome, Some(DialOutcome::Success)));
        if libp2p_ok {
            stats.libp2p_reachable_authorities += 1;
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

                // Private addresses are never dialed, so keeping them out of
                // the dial buckets leaves both blocks with the same
                // denominator.
                match &a.dial_outcome {
                    Some(DialOutcome::Success) => stats.dial_success += 1,
                    Some(DialOutcome::Failed(_)) => stats.dial_failed += 1,
                    Some(DialOutcome::Skipped(_)) => stats.dial_skipped += 1,
                    None => stats.dial_pending += 1,
                }
            } else {
                stats.private_addresses += 1;
            }
        }
    }

    stats
}

/// Compute statistics over every node reached during the crawl, from the
/// identify responses collected while walking the DHT.
fn compute_all_nodes_stats(
    reached_peers: &HashSet<PeerId>,
    peer_info: &HashMap<PeerId, IdentifyInfo>,
    validator_peers: &HashSet<PeerId>,
) -> AllNodesStats {
    let mut stats = AllNodesStats {
        reached_peers: reached_peers.len(),
        identified: peer_info.len(),
        validators: 0,
        non_validators: 0,
        transports: TransportStats::default(),
        no_known_transport: 0,
        agent_versions: HashMap::new(),
    };

    for (peer_id, info) in peer_info {
        if validator_peers.contains(peer_id) {
            stats.validators += 1;
        } else {
            stats.non_validators += 1;
        }

        let transports: HashSet<&'static str> = info
            .listen_addrs
            .iter()
            .filter_map(classify_transport)
            .collect();
        if transports.is_empty() {
            stats.no_known_transport += 1;
        }
        for transport in transports {
            match transport {
                "tcp" => stats.transports.tcp += 1,
                "websocket" => stats.transports.websocket += 1,
                "webrtc" => stats.transports.webrtc += 1,
                "quic" => stats.transports.quic += 1,
                _ => (),
            }
        }

        let normalized = normalize_agent_version(&info.agent_version);
        *stats.agent_versions.entry(normalized).or_insert(0) += 1;
    }

    stats
}

/// Print the global summary with formatted statistics.
fn print_global_summary(
    w: &mut DualWriter,
    stats: &GlobalStats,
    all_nodes: &AllNodesStats,
    network_backend: NetworkBackend,
) -> io::Result<()> {
    let pct = |n: usize, d: usize| -> String {
        if d > 0 {
            format!("{:.1}%", n as f64 / d as f64 * 100.0)
        } else {
            "N/A".to_string()
        }
    };

    writeln!(w)?;
    writeln!(
        w,
        "════════════════════════════════════════════════════════════════════════"
    )?;
    writeln!(w, "                          GLOBAL SUMMARY")?;
    writeln!(
        w,
        "════════════════════════════════════════════════════════════════════════"
    )?;
    writeln!(w)?;

    writeln!(w, "  Authorities")?;
    writeln!(
        w,
        "  ├─ Total (runtime API):          {:>6}",
        stats.total_authorities
    )?;
    writeln!(
        w,
        "  ├─ With on-chain identity:       {:>6} ({})",
        stats.with_identity,
        pct(stats.with_identity, stats.total_authorities)
    )?;
    writeln!(
        w,
        "  ├─ With DHT records:             {:>6} ({})",
        stats.with_dht_records,
        pct(stats.with_dht_records, stats.total_authorities)
    )?;
    writeln!(
        w,
        "  ├─ With Peer ID:                 {:>6} ({})",
        stats.with_peer_id,
        pct(stats.with_peer_id, stats.total_authorities)
    )?;
    writeln!(
        w,
        "  └─ Identified (p2p):             {:>6} ({})",
        stats.identified,
        pct(stats.identified, stats.total_authorities)
    )?;
    writeln!(w)?;

    writeln!(w, "  Addresses")?;
    writeln!(
        w,
        "  ├─ Total:                        {:>6}",
        stats.total_addresses
    )?;
    writeln!(
        w,
        "  ├─ Public:                       {:>6} ({})",
        stats.public_addresses,
        pct(stats.public_addresses, stats.total_addresses)
    )?;
    writeln!(
        w,
        "  └─ Private:                      {:>6} ({})",
        stats.private_addresses,
        pct(stats.private_addresses, stats.total_addresses)
    )?;
    writeln!(w)?;

    writeln!(w, "  Connectivity")?;
    writeln!(
        w,
        "  ├─ Reachable authorities (>=1):  {:>6} ({})",
        stats.reachable_authorities,
        pct(stats.reachable_authorities, stats.total_authorities)
    )?;
    writeln!(
        w,
        "  ├─ Fully reachable (all public): {:>6} ({})",
        stats.fully_reachable_authorities,
        pct(stats.fully_reachable_authorities, stats.total_authorities)
    )?;
    writeln!(
        w,
        "  ├─ Public addrs reachable:  {:>6}/{:<6} ({})",
        stats.reachable_public,
        stats.public_addresses,
        pct(stats.reachable_public, stats.public_addresses)
    )?;
    writeln!(
        w,
        "  └─ Public addrs unreachable:{:>6}/{:<6} ({})",
        stats.unreachable_public,
        stats.public_addresses,
        pct(stats.unreachable_public, stats.public_addresses)
    )?;
    writeln!(w)?;

    // Only one connection per peer is probed at a time, so the address level
    // numbers below cover the addresses that were actually dialed, and the
    // authority level number covers everything we managed to talk to.
    let dial_probed = stats.dial_success + stats.dial_failed;
    writeln!(
        w,
        "  {} Dials (noise + yamux, public addresses)",
        network_backend.title()
    )?;
    writeln!(
        w,
        "  ├─ Authorities connected:        {:>6} ({})",
        stats.libp2p_reachable_authorities,
        pct(stats.libp2p_reachable_authorities, stats.total_authorities)
    )?;
    writeln!(w, "  ├─ Addresses probed:             {:>6}", dial_probed)?;
    writeln!(
        w,
        "  ├─ Connected:                    {:>6} ({})",
        stats.dial_success,
        pct(stats.dial_success, dial_probed)
    )?;
    writeln!(
        w,
        "  ├─ Failed:                       {:>6} ({})",
        stats.dial_failed,
        pct(stats.dial_failed, dial_probed)
    )?;
    writeln!(
        w,
        "  ├─ Not probed:                   {:>6}",
        stats.dial_skipped
    )?;
    writeln!(
        w,
        "  └─ Pending:                      {:>6}",
        stats.dial_pending
    )?;
    writeln!(w)?;

    // A validator advertising several transports is counted once per
    // transport, so the buckets do not add up to the number of validators.
    writeln!(w, "  Transports (DHT + identify addresses)")?;
    writeln!(
        w,
        "  ├─ TCP:                          {:>6} ({})",
        stats.transports.tcp,
        pct(stats.transports.tcp, stats.total_authorities)
    )?;
    writeln!(
        w,
        "  ├─ WebSocket:                    {:>6} ({})",
        stats.transports.websocket,
        pct(stats.transports.websocket, stats.total_authorities)
    )?;
    let (webrtc_branch, quic) = if stats.transports.quic > 0 {
        ("├─", true)
    } else {
        ("└─", false)
    };
    writeln!(
        w,
        "  {} WebRTC:                       {:>6} ({})",
        webrtc_branch,
        stats.transports.webrtc,
        pct(stats.transports.webrtc, stats.total_authorities)
    )?;
    if quic {
        writeln!(
            w,
            "  └─ QUIC:                         {:>6} ({})",
            stats.transports.quic,
            pct(stats.transports.quic, stats.total_authorities)
        )?;
    }

    if !stats.agent_versions.is_empty() {
        writeln!(w)?;
        writeln!(w, "  Agent Distribution (identify handshake)")?;
        let mut versions: Vec<_> = stats.agent_versions.iter().collect();
        versions.sort_by(|a, b| b.1.cmp(a.1));
        // Every version was read from an identify response, so the counts add
        // up to the number of identified authorities.
        let identified: usize = versions.iter().map(|(_, count)| **count).sum();
        writeln!(w, "  ├─ Identify responses:           {:>6}", identified)?;
        let len = versions.len();
        for (i, (version, count)) in versions.iter().enumerate() {
            let branch = if i == len - 1 { "└─" } else { "├─" };
            let v = if version.len() > 40 {
                format!("{}...", &version[..37])
            } else {
                version.to_string()
            };
            writeln!(
                w,
                "  {} {:<42} {:>4} ({})",
                branch,
                v,
                count,
                pct(**count, identified)
            )?;
        }
    }

    // Everything the crawl talked to, not just the validators: Kademlia
    // walks through many regular network nodes on the way to the records.
    writeln!(w)?;
    writeln!(w, "  Network Nodes (entire crawl, validators + others)")?;
    writeln!(
        w,
        "  ├─ Peers connected:              {:>6}",
        all_nodes.reached_peers
    )?;
    writeln!(
        w,
        "  ├─ Identified (identify):        {:>6} ({})",
        all_nodes.identified,
        pct(all_nodes.identified, all_nodes.reached_peers)
    )?;
    writeln!(
        w,
        "  ├─ Validators:                   {:>6}",
        all_nodes.validators
    )?;
    writeln!(
        w,
        "  └─ Other nodes:                  {:>6}",
        all_nodes.non_validators
    )?;
    writeln!(w)?;

    // A node listening on several transports is counted once per transport,
    // so the buckets do not add up to the number of identified nodes.
    writeln!(w, "  Network Transports (identify addresses, all nodes)")?;
    writeln!(
        w,
        "  ├─ TCP:                          {:>6} ({})",
        all_nodes.transports.tcp,
        pct(all_nodes.transports.tcp, all_nodes.identified)
    )?;
    writeln!(
        w,
        "  ├─ WebSocket:                    {:>6} ({})",
        all_nodes.transports.websocket,
        pct(all_nodes.transports.websocket, all_nodes.identified)
    )?;
    writeln!(
        w,
        "  ├─ WebRTC:                       {:>6} ({})",
        all_nodes.transports.webrtc,
        pct(all_nodes.transports.webrtc, all_nodes.identified)
    )?;
    if all_nodes.transports.quic > 0 {
        writeln!(
            w,
            "  ├─ QUIC:                         {:>6} ({})",
            all_nodes.transports.quic,
            pct(all_nodes.transports.quic, all_nodes.identified)
        )?;
    }
    writeln!(
        w,
        "  └─ No known transport:           {:>6} ({})",
        all_nodes.no_known_transport,
        pct(all_nodes.no_known_transport, all_nodes.identified)
    )?;

    if !all_nodes.agent_versions.is_empty() {
        // The whole network runs far more releases than the validator set, so
        // only the most common ones are printed; the JSON report keeps them all.
        const MAX_NETWORK_VERSIONS: usize = 12;

        writeln!(w)?;
        writeln!(w, "  Network Agent Distribution (all identified nodes)")?;
        let mut versions: Vec<_> = all_nodes.agent_versions.iter().collect();
        versions.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

        let shown = versions.len().min(MAX_NETWORK_VERSIONS);
        let rest: usize = versions[shown..].iter().map(|(_, count)| **count).sum();
        for (i, (version, count)) in versions.iter().take(shown).enumerate() {
            let branch = if i == shown - 1 && rest == 0 {
                "└─"
            } else {
                "├─"
            };
            let v = if version.len() > 40 {
                format!("{}...", &version[..37])
            } else {
                version.to_string()
            };
            writeln!(
                w,
                "  {} {:<42} {:>4} ({})",
                branch,
                v,
                count,
                pct(**count, all_nodes.identified)
            )?;
        }
        if rest > 0 {
            writeln!(
                w,
                "  └─ {:<42} {:>4} ({})",
                format!("... {} more versions", versions.len() - shown),
                rest,
                pct(rest, all_nodes.identified)
            )?;
        }
    }

    writeln!(w)?;
    Ok(())
}

/// Entry function for the `authority-check` CLI command.
///
/// Discovers authorities via the runtime API, scrapes their DHT records
/// to collect advertised multiaddresses, then checks TCP connectivity
/// to each address. Prints per-authority results and global statistics.
///
/// The DHT crawl and the dial probes run on the selected `network_backend`;
/// everything else, including the report, is shared.
pub async fn check_authorities(
    url: String,
    genesis: Option<String>,
    bootnodes: Vec<String>,
    timeout: Duration,
    dial_timeout: Duration,
    address_format: Option<String>,
    query_timeout: Duration,
    identity_rpc: Option<String>,
    show_failing_only: bool,
    json_output: Option<PathBuf>,
    network_backend: NetworkBackend,
) -> Result<(), Box<dyn Error>> {
    let rpc_url = Url::parse(&url)?;

    // Create cache directory and log file. Runs on the default backend keep
    // their historical file names.
    let cache_file = match fs::create_dir_all("cache") {
        Ok(()) => {
            let chain = detect_chain_name(&rpc_url).unwrap_or("unknown").to_string();
            let backend_suffix = match network_backend {
                NetworkBackend::Libp2p => "",
                NetworkBackend::Litep2p => "-litep2p",
            };
            let timestamp = chrono::Local::now().format("%Y-%m-%d-%H-%M-%S");
            let path = format!("cache/{}{}-{}.logs", chain, backend_suffix, timestamp);
            match File::create(&path) {
                Ok(f) => {
                    eprintln!("       Logging output to {}", path);
                    Some(f)
                }
                Err(e) => {
                    eprintln!("       Warning: could not create log file {}: {}", path, e);
                    None
                }
            }
        }
        Err(e) => {
            eprintln!("       Warning: could not create cache directory: {}", e);
            None
        }
    };

    let mut w = DualWriter::new(cache_file);

    writeln!(
        w,
        "════════════════════════════════════════════════════════════════════════"
    )?;
    writeln!(w, "                         AUTHORITY CHECK")?;
    writeln!(
        w,
        "════════════════════════════════════════════════════════════════════════"
    )?;
    writeln!(w)?;
    writeln!(w, "       Network backend: {}", network_backend.name())?;
    writeln!(w)?;

    // Resolve SS58 prefix: use provided format name or fetch from RPC.
    let version = match address_format {
        Some(fmt) => {
            let format_registry = ss58_registry::Ss58AddressFormatRegistry::try_from(fmt.as_str())
                .map_err(|err| format!("Cannot parse the provided address format: {:?}", err))?;
            let v: ss58_registry::Ss58AddressFormat = format_registry.into();
            v.prefix()
        }
        None => {
            writeln!(w, "       No address format provided, fetching from RPC...")?;
            let prefix = fetch_ss58_prefix(rpc_url.clone()).await?;
            let name = ss58_registry::Ss58AddressFormatRegistry::try_from(
                ss58_registry::Ss58AddressFormat::custom(prefix),
            );
            match name {
                Ok(registry) => writeln!(
                    w,
                    "       Address format: {:?} (prefix: {})",
                    registry, prefix
                )?,
                Err(_) => writeln!(w, "       SS58 prefix: {}", prefix)?,
            }
            writeln!(w)?;
            prefix
        }
    };

    // Resolve genesis hash: use provided one or fetch from RPC.
    let genesis = match genesis {
        Some(g) => g,
        None => {
            writeln!(w, "       No genesis hash provided, fetching from RPC...")?;
            let hash = fetch_genesis_hash(rpc_url.clone()).await?;
            writeln!(w, "       Genesis hash: 0x{}", hash)?;
            writeln!(w)?;
            hash
        }
    };

    // Resolve bootnodes: use provided ones, fetch from RPC, and merge with published chainspec.
    let bootnodes = resolve_bootnodes(&rpc_url, bootnodes, &mut w).await?;

    writeln!(w, "[1/4] Fetching authorities from runtime API...")?;
    let authorities = runtime_api_autorities(rpc_url.clone()).await?;
    writeln!(w, "       Found {} authorities", authorities.len())?;
    writeln!(w)?;

    let identity_url = identity_rpc
        .map(|s| Url::parse(&s))
        .transpose()
        .map_err(|e| format!("Invalid --identity-rpc URL: {}", e))?;

    writeln!(w, "[2/4] Resolving on-chain identities...")?;
    let IdentityResult {
        names: identity_names,
        stash_accounts,
    } = fetch_identity_names(rpc_url.clone(), identity_url, &authorities, &mut w).await;
    writeln!(w)?;

    writeln!(
        w,
        "[3/4] Discovering authority DHT records (timeout: {}s, backend: {})...",
        timeout.as_secs(),
        network_backend.name()
    )?;
    // Extract the results and drop the network stack so its connections and
    // file descriptors are released before we open new TCP sockets in Phase 4.
    let (authority_to_details, peer_info, dial_outcomes, reached_peers) = match network_backend {
        NetworkBackend::Libp2p => {
            let swarm = build_swarm(genesis, bootnodes, query_timeout).await?;
            let mut discovery = AuthorityDiscovery::new(swarm, authorities.clone(), timeout);
            discovery.set_show_progress(true);
            discovery.discover().await;

            let (authority_to_details, peer_info, dial_outcomes, reached_peers) =
                discovery.into_results();
            let peer_info: HashMap<PeerId, IdentifyInfo> = peer_info
                .into_iter()
                .map(|(peer, info)| (peer, IdentifyInfo::from(info)))
                .collect();
            (
                authority_to_details,
                peer_info,
                dial_outcomes,
                reached_peers,
            )
        }
        NetworkBackend::Litep2p => {
            let mut discovery = Litep2pAuthorityDiscovery::new(
                &genesis,
                bootnodes,
                authorities.clone(),
                timeout,
                query_timeout,
            )?;
            discovery.set_show_progress(true);
            discovery.discover().await;
            discovery.into_results()
        }
    };

    let dht_count = authority_to_details.len();
    let identified_authorities = authorities
        .iter()
        .filter(|auth| {
            authority_to_details
                .get(*auth)
                .and_then(|addrs| addrs.iter().find_map(get_peer_id))
                .map_or(false, |pid| peer_info.contains_key(&pid))
        })
        .count();
    writeln!(
        w,
        "       DHT records: {}/{} | Identified authorities: {}/{}",
        dht_count,
        authorities.len(),
        identified_authorities,
        authorities.len(),
    )?;
    writeln!(
        w,
        "       Network peers reached: {} | Identified: {}",
        reached_peers.len(),
        peer_info.len(),
    )?;

    // Report libp2p dial results. Addresses of a peer that is already connected
    // are not dialed a second time, so they are reported as not probed instead
    // of as failures.
    //
    // Only authority addresses are counted: the outcome map also holds the
    // connections Kademlia opened to the rest of the network while crawling.
    let mut dial_success = 0usize;
    let mut dial_failed = 0usize;
    let mut dial_skipped = 0usize;
    let mut dial_pending = 0usize;
    let mut total_addrs = 0usize;
    for addr in authority_to_details.values().flatten() {
        total_addrs += 1;
        match dial_outcomes.get(addr) {
            Some(DialOutcome::Success) => dial_success += 1,
            Some(DialOutcome::Failed(_)) => dial_failed += 1,
            Some(DialOutcome::Skipped(_)) => dial_skipped += 1,
            None => dial_pending += 1,
        }
    }
    let dial_probed = dial_success + dial_failed;
    let probed_pct = |n: usize| -> f64 {
        if dial_probed > 0 {
            n as f64 / dial_probed as f64 * 100.0
        } else {
            0.0
        }
    };
    writeln!(w)?;
    writeln!(
        w,
        "       {} dial results ({} of {} addresses probed):",
        network_backend.title(),
        dial_probed,
        total_addrs
    )?;
    writeln!(
        w,
        "       \u{251c}\u{2500} Connected:  {:>6} ({:.1}%)",
        dial_success,
        probed_pct(dial_success)
    )?;
    writeln!(
        w,
        "       \u{251c}\u{2500} Failed:     {:>6} ({:.1}%)",
        dial_failed,
        probed_pct(dial_failed)
    )?;
    writeln!(w, "       \u{251c}\u{2500} Not probed: {:>6}", dial_skipped)?;
    writeln!(w, "       \u{2514}\u{2500} Pending:    {:>6}", dial_pending)?;
    writeln!(w)?;

    // Phase 3: TCP connectivity checks on every discovered address.
    let mut pending_checks: Vec<(usize, Multiaddr, bool)> = Vec::new();
    for (idx, authority) in authorities.iter().enumerate() {
        if let Some(addrs) = authority_to_details.get(authority) {
            for addr in addrs {
                let is_pub = is_public_address(addr);
                pending_checks.push((idx, addr.clone(), is_pub));
            }
        }
    }

    let public_count = pending_checks.iter().filter(|(_, _, p)| *p).count();
    writeln!(
        w,
        "[4/4] Checking connectivity ({} addresses, {} public, timeout: {}s/addr)...",
        pending_checks.len(),
        public_count,
        dial_timeout.as_secs()
    )?;

    let mut check_results = run_connectivity_checks(pending_checks, dial_timeout, &mut w).await;

    // Enrich each address check with the p2p dial outcome.
    for checks in check_results.values_mut() {
        for check in checks.iter_mut() {
            if let Some(ref addr) = check.full_address {
                check.dial_outcome = dial_outcomes.get(addr).cloned();
            }
        }
    }
    writeln!(w)?;

    // Build per-authority results.
    let mut results: Vec<AuthorityResult> = Vec::with_capacity(authorities.len());

    for (idx, authority) in authorities.iter().enumerate() {
        let authority_ss58 = to_ss58(authority, version);
        let stash_ss58 = stash_accounts.get(authority).map(|s| to_ss58(s, version));

        let identity_name = identity_names.get(authority).cloned();

        let Some(addrs) = authority_to_details.get(authority) else {
            results.push(AuthorityResult {
                authority_ss58,
                stash_ss58,
                identity_name,
                peer_id: None,
                agent_version: None,
                has_dht_record: false,
                identify_addresses: Vec::new(),
                transports: Vec::new(),
                addresses: Vec::new(),
            });
            continue;
        };

        let peer_id = addrs.iter().find_map(get_peer_id);
        let info = peer_id.and_then(|pid| peer_info.get(&pid));
        let agent_version = info.map(|info| info.agent_version.clone());

        // Addresses the peer claims to listen on, taken from the identify
        // response. These complement the DHT record: the record only holds
        // what the authority chose to publish.
        let identify_addresses: Vec<String> = info
            .map(|info| info.listen_addrs.iter().map(|a| a.to_string()).collect())
            .unwrap_or_default();

        let mut transports: HashSet<&'static str> =
            addrs.iter().filter_map(classify_transport).collect();
        if let Some(info) = info {
            transports.extend(info.listen_addrs.iter().filter_map(classify_transport));
        }
        let mut transports: Vec<&'static str> = transports.into_iter().collect();
        transports.sort_unstable();

        let addresses = check_results.remove(&idx).unwrap_or_default();

        results.push(AuthorityResult {
            authority_ss58,
            stash_ss58,
            identity_name,
            peer_id: peer_id.map(|p| p.to_string()),
            agent_version,
            has_dht_record: true,
            identify_addresses,
            transports,
            addresses,
        });
    }

    // Print per-authority details.
    for (i, result) in results.iter().enumerate() {
        if show_failing_only && !is_authority_failing(result) {
            continue;
        }
        print_authority_result(&mut w, result, i)?;
    }

    // Print global summary.
    let stats = compute_global_stats(&results);
    let validator_peers: HashSet<PeerId> = authority_to_details
        .values()
        .flatten()
        .filter_map(get_peer_id)
        .collect();
    let all_nodes = compute_all_nodes_stats(&reached_peers, &peer_info, &validator_peers);
    print_global_summary(&mut w, &stats, &all_nodes, network_backend)?;

    // Write JSON report if requested.
    if let Some(ref path) = json_output {
        let report = JsonReport {
            chain: detect_chain_name(&rpc_url),
            rpc_url: rpc_url.as_str(),
            network_backend,
            authorities: &results,
            stats: &stats,
            all_nodes: &all_nodes,
        };
        let file = File::create(path)?;
        serde_json::to_writer_pretty(file, &report)?;
        eprintln!("       JSON report written to {}", path.display());
    }

    w.flush()?;
    Ok(())
}
