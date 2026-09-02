use crate::utils::{build_swarm, dial_error_message, is_dialable_transport, is_public_address};
use codec::Decode;
use futures::FutureExt;
use futures::StreamExt;
use jsonrpsee::{
    client_transport::ws::{Url, WsTransportClientBuilder},
    core::client::{Client, ClientT},
    rpc_params,
};
use libp2p::{
    core::ConnectedPoint,
    identify::Info,
    kad::{Event as KademliaEvent, GetRecordOk, QueryId, QueryResult, RecordKey as KademliaKey},
    swarm::{dial_opts::DialOpts, ConnectionId, SwarmEvent},
    Multiaddr, PeerId, Swarm,
};
use rand::{seq::SliceRandom, thread_rng};
use serde::Deserialize;
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use subp2p_explorer::{
    peer_behavior::PeerInfoEvent,
    util::authorities::{decode_dht_record, hash_authority_id},
    util::crypto::sr25519,
    util::p2p::get_peer_id,
    util::ss58::to_ss58,
    Behaviour, BehaviourEvent,
};

/// Construct a jsonrpc client to communicate with the target node.
pub async fn client(url: Url) -> Result<Client, Box<dyn std::error::Error>> {
    let (sender, receiver) = WsTransportClientBuilder::default().build(url).await?;

    Ok(Client::builder()
        .max_buffer_capacity_per_subscription(4096)
        .build_with_tokio(sender, receiver))
}

/// Fetch bootnodes from the chain spec via the RPC endpoint.
///
/// Calls `sync_state_genSyncSpec` to retrieve the full chain spec and extracts
/// the `bootNodes` array.
pub(crate) async fn fetch_bootnodes_from_rpc(
    url: Url,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let client = client(url).await?;

    let spec: serde_json::Value = client
        .request("sync_state_genSyncSpec", rpc_params![true])
        .await?;

    let bootnodes = spec
        .get("bootNodes")
        .ok_or("Chain spec missing `bootNodes` field")?
        .as_array()
        .ok_or("Invalid `bootNodes` format, expected array")?
        .iter()
        .filter_map(|node| node.as_str().map(|s| s.to_string()))
        .collect();

    Ok(bootnodes)
}

/// Known chains whose published chainspecs are available at
/// `https://paritytech.github.io/chainspecs/{chain}/relaychain/chainspec.json`.
const KNOWN_CHAINS: &[&str] = &["kusama", "paseo", "westend", "polkadot"];

/// Detect a known chain name from the RPC URL.
///
/// Checks both the hostname and path for "kusama", "paseo", "westend",
/// "polkadot" (in that order — kusama before polkadot because
/// `kusama-rpc.polkadot.io` contains both). This also handles URLs like
/// `wss://rpc.ibp.network/paseo` where the chain name is in the path.
pub fn detect_chain_name(url: &Url) -> Option<&'static str> {
    let host = url.host_str().unwrap_or("");
    let path = url.path();
    KNOWN_CHAINS
        .iter()
        .find(|&&chain| host.contains(chain) || path.contains(chain))
        .copied()
}

/// Fetch bootnodes from a published chainspec for a known chain.
///
/// Downloads `https://paritytech.github.io/chainspecs/{chain}/relaychain/chainspec.json`
/// and extracts the `bootNodes` array.
pub(crate) async fn fetch_bootnodes_from_chainspec(
    chain: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = format!(
        "https://paritytech.github.io/chainspecs/{}/relaychain/chainspec.json",
        chain
    );
    let resp: serde_json::Value = reqwest::get(&url).await?.json().await?;
    let bootnodes = resp
        .get("bootNodes")
        .ok_or("Published chainspec missing `bootNodes` field")?
        .as_array()
        .ok_or("Invalid `bootNodes` format, expected array")?
        .iter()
        .filter_map(|node| node.as_str().map(|s| s.to_string()))
        .collect();
    Ok(bootnodes)
}

/// Resolve bootnodes by combining CLI-provided, RPC-fetched, and published chainspec sources.
///
/// 1. Uses CLI bootnodes if provided, otherwise fetches from RPC.
/// 2. If a known chain is detected from the RPC URL, also downloads published chainspec bootnodes.
/// 3. Merges and deduplicates all bootnodes (exact string match).
///
/// Chainspec download failures are logged as warnings and do not abort the process.
pub(crate) async fn resolve_bootnodes(
    rpc_url: &Url,
    cli_bootnodes: Vec<String>,
    w: &mut impl Write,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut bootnodes = if cli_bootnodes.is_empty() {
        writeln!(
            w,
            "       No bootnodes provided, fetching from chain spec via RPC..."
        )?;
        let fetched = fetch_bootnodes_from_rpc(rpc_url.clone()).await?;
        writeln!(w, "       Fetched {} bootnodes from RPC", fetched.len())?;
        fetched
    } else {
        cli_bootnodes
    };

    if let Some(chain) = detect_chain_name(rpc_url) {
        writeln!(
            w,
            "       Detected known chain \"{}\", downloading published chainspec bootnodes...",
            chain
        )?;
        match fetch_bootnodes_from_chainspec(chain).await {
            Ok(extra) => {
                let unique_peers: HashSet<_> = extra
                    .iter()
                    .filter_map(|addr| addr.rsplit("/p2p/").next())
                    .collect();
                writeln!(
                    w,
                    "       Fetched from chainspec online {} addresses and {} bootnodes",
                    extra.len(),
                    unique_peers.len()
                )?;
                let mut seen: HashSet<String> = bootnodes.drain(..).collect();
                let before = seen.len();
                seen.extend(extra);
                writeln!(
                    w,
                    "       Merged to {} unique addresses ({} new from chainspec)",
                    seen.len(),
                    seen.len() - before
                )?;
                bootnodes = seen.into_iter().collect();
            }
            Err(e) => {
                log::warn!(
                    "Failed to fetch published chainspec bootnodes for {}: {}",
                    chain,
                    e
                );
                writeln!(
                    w,
                    "       Warning: could not fetch published chainspec bootnodes: {}",
                    e
                )?;
            }
        }
    }

    writeln!(w)?;
    Ok(bootnodes)
}

/// Fetch the genesis hash from the RPC endpoint.
///
/// Calls `chain_getBlockHash(0)` and returns the hex-encoded hash (without `0x` prefix).
pub(crate) async fn fetch_genesis_hash(url: Url) -> Result<String, Box<dyn std::error::Error>> {
    let client = client(url).await?;

    let hash: String = client
        .request("chain_getBlockHash", rpc_params![0u32])
        .await?;

    Ok(hash.trim_start_matches("0x").to_string())
}

/// Fetch the SS58 address prefix from the RPC endpoint via `system_properties`.
pub(crate) async fn fetch_ss58_prefix(url: Url) -> Result<u16, Box<dyn std::error::Error>> {
    let client = client(url).await?;

    let props: serde_json::Value = client.request("system_properties", rpc_params![]).await?;

    let prefix = props
        .get("ss58Format")
        .ok_or("system_properties missing `ss58Format` field")?
        .as_u64()
        .ok_or("Invalid `ss58Format`, expected integer")? as u16;

    Ok(prefix)
}

/// Call the runtime API of the target node to retrive the current set
/// of authorities.
///
/// This method calls into `AuthorityDiscoveryApi_authorities` runtime API.
pub(crate) async fn runtime_api_autorities(
    url: Url,
) -> Result<Vec<sr25519::PublicKey>, Box<dyn std::error::Error>> {
    let client = client(url).await?;

    // State call provides the result hex-encoded.
    let raw: String = client
        .request(
            "state_call",
            rpc_params!["AuthorityDiscoveryApi_authorities", "0x"],
        )
        .await?;
    let raw = raw
        .strip_prefix("0x")
        .expect("Substrate API returned invalid hex");

    let bytes = hex::decode(raw)?;

    let authorities: Vec<sr25519::PublicKey> = Decode::decode(&mut &bytes[..])?;
    Ok(authorities)
}

/// The maximum number of Kademlia `get-records` queried a time.
const MAX_QUERIES: usize = 128;

/// Exit the discovery early once every authority record was found, all dials
/// resolved and the swarm has been quiet for this long.
const COMPLETE_QUIET_SECS: u64 = 5;

/// Exit the discovery early when some records were never found but nothing
/// made progress for this long. Two resubmission rounds
/// ([`AuthorityDiscovery::interval_resubmit`]) fit in this window, so a record
/// that can still be found gets its chance before the crawl gives up.
const STALL_QUIET_SECS: u64 = 30;

/// Discover the authorities on the network.
pub struct AuthorityDiscovery {
    /// Drive the network behavior.
    swarm: Swarm<Behaviour>,

    /// In flight `get-record` kademlia queries to ensure that a maximum of `MAX_QUERIES` are in flight.
    queries: HashMap<QueryId, sr25519::PublicKey>,
    /// In flight `get-closest-peers` kademlia queries to force the discovery of unidentified peers.
    queries_discovery: HashSet<QueryId>,

    /// Map the in-flight kademlia queries to the authority ids.
    records_keys: HashMap<KademliaKey, sr25519::PublicKey>,
    /// Peer details obtained from the DHT records.
    peer_details: HashMap<PeerId, PeerDetails>,
    /// Peer information from the identify protocol. This includes the version of the peer.
    peer_info: HashMap<PeerId, Info>,
    authority_to_details: HashMap<sr25519::PublicKey, HashSet<Multiaddr>>,

    /// Initially provided authority list.
    authorities: Vec<sr25519::PublicKey>,
    /// Query index.
    query_index: usize,

    /// Encountered DHT errors, either from decoding or protocol transport.
    dht_errors: usize,

    /// Remaining authorities to query.
    remaining_authorities: HashSet<sr25519::PublicKey>,
    /// Finished DHT queries for authority records.
    finished_query: bool,

    /// Time of the last log line.
    old_log: std::time::Instant,
    /// Time of the last discovery progress: a new authority record, a resolved
    /// probe dial, or an identify response from a validator. Used to exit
    /// early once the crawl goes quiet instead of waiting for the timeout.
    last_progress: std::time::Instant,
    /// Interval at which to resubmit the remaining queries.
    interval_resubmit: tokio::time::Interval,
    /// Interval at which to bail out.
    interval_exit: tokio::time::Interval,

    /// Whether to print an interactive progress bar to stdout.
    show_progress: bool,
    /// When the discovery process started.
    start_time: std::time::Instant,
    /// Timeout duration for display purposes.
    timeout_secs: u64,

    /// Per-address libp2p dial outcomes (noise + yamux upgrade).
    dial_outcomes: HashMap<Multiaddr, DialOutcome>,
    /// Addresses already queued for dialing. Deduplicates addresses advertised
    /// by more than one authority record.
    dialed_addresses: HashSet<Multiaddr>,
    /// Addresses waiting to be dialed, per peer.
    queued_dials: HashMap<PeerId, VecDeque<Multiaddr>>,
    /// Dials we initiated ourselves, keyed by connection id. Dials started by
    /// Kademlia during the crawl are not tracked here: they carry no
    /// information about a specific advertised address.
    active_dials: HashMap<ConnectionId, ActiveDial>,

    /// Every distinct peer a connection was established with during the crawl,
    /// validators and regular network nodes alike.
    reached_peers: HashSet<PeerId>,
}

/// The peer details extracted from the DHT.
#[derive(Clone, Serialize, Deserialize)]
pub struct PeerDetails {
    /// Authority ID from the runtime API.
    #[allow(unused)]
    authority_id: sr25519::PublicKey,
    /// Discovered from the DHT.
    addresses: HashSet<Multiaddr>,
}

impl PeerDetails {
    #[allow(dead_code)]
    pub fn addresses(&self) -> &HashSet<Multiaddr> {
        &self.addresses
    }

    #[allow(dead_code)]
    pub fn authority_id(&self) -> &sr25519::PublicKey {
        &self.authority_id
    }
}

/// Outcome of dialing a single address through the libp2p stack
/// (noise handshake and yamux multiplexing).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", content = "reason")]
pub enum DialOutcome {
    /// Connection established successfully.
    Success,
    /// Dial failed with an error.
    Failed(String),
    /// The address was never dialed: it is not routable from here, its
    /// transport is not supported, or the peer was already connected through
    /// another address.
    Skipped(String),
}

/// A dial we initiated to probe one specific advertised address.
#[derive(Debug)]
struct ActiveDial {
    /// Peer the address belongs to.
    peer: PeerId,
    /// Address being probed.
    address: Multiaddr,
    /// Set when the peer became connected through another route while this
    /// dial was in flight. Substrate nodes keep a single connection per peer
    /// and close the redundant one, so the resulting error says nothing about
    /// the address itself.
    superseded: bool,
}

impl AuthorityDiscovery {
    /// Constructs a new [`AuthorityDiscovery`].
    pub fn new(
        swarm: Swarm<Behaviour>,
        authorities: Vec<sr25519::PublicKey>,
        timeout: std::time::Duration,
    ) -> Self {
        AuthorityDiscovery {
            swarm,
            queries: HashMap::with_capacity(1024),

            records_keys: HashMap::with_capacity(1024),

            queries_discovery: HashSet::with_capacity(1024),
            peer_info: HashMap::with_capacity(1024),
            peer_details: HashMap::with_capacity(1024),
            authority_to_details: HashMap::with_capacity(1024),

            authorities: authorities.clone(),
            query_index: 0,

            dht_errors: 0,
            remaining_authorities: authorities.into_iter().collect(),
            finished_query: false,

            old_log: std::time::Instant::now(),
            last_progress: std::time::Instant::now(),
            interval_resubmit: tokio::time::interval(std::time::Duration::from_secs(15)),
            interval_exit: tokio::time::interval(timeout),

            show_progress: false,
            start_time: std::time::Instant::now(),
            timeout_secs: timeout.as_secs(),

            dial_outcomes: HashMap::with_capacity(4096),
            dialed_addresses: HashSet::with_capacity(4096),
            queued_dials: HashMap::with_capacity(1024),
            active_dials: HashMap::with_capacity(1024),

            reached_peers: HashSet::with_capacity(4096),
        }
    }

    /// Query the DHT for the records of the authorities.
    fn query_dht_records(&mut self, authorities: impl IntoIterator<Item = sr25519::PublicKey>) {
        // Make a query for every authority.
        for authority in authorities {
            let key = hash_authority_id(&authority);
            self.records_keys.insert(key.clone(), authority);

            let id = self.swarm.behaviour_mut().discovery.get_record(key);
            self.queries.insert(id, authority);
        }
    }

    /// Query the DHT for the closest peers of the authorities that
    /// are not reacheable at the moment. This function is called
    /// after the authorities are discovered from the DHT to avoid
    /// running out of file descriptors.
    ///
    /// Note: they may never be reachable due to NAT.
    fn query_peer_info(&mut self) {
        // This is not correlated with the `MAX_QUERIES`.
        const MAX_DISCOVERY_QUERIES: usize = 32;

        if self.queries_discovery.len() < MAX_DISCOVERY_QUERIES {
            let query_num = MAX_DISCOVERY_QUERIES - self.queries_discovery.len();
            for _ in 0..query_num {
                self.queries_discovery.insert(
                    self.swarm
                        .behaviour_mut()
                        .discovery
                        .get_closest_peers(PeerId::random()),
                );
            }
        }
    }

    /// Submit at most `MAX_QUERIES` DHT queries to find authority records.
    ///
    /// After one query is submitted for every authority this method will
    /// resubmit the DHT queries for the remaining authorities.
    fn advance_dht_queries(&mut self) {
        // Add more DHT queries from the initial authority list.
        while self.queries.len() < MAX_QUERIES {
            if let Some(next) = self.authorities.get(self.query_index) {
                self.query_dht_records(std::iter::once(*next));
                self.query_index += 1;
            } else {
                break;
            }
        }

        // Backfill empty slots with remaining (not-yet-found) authorities
        // so that slots freed by completed queries are reused immediately
        // instead of waiting for the periodic resubmit timer.
        if self.query_index >= self.authorities.len() && self.queries.len() < MAX_QUERIES {
            let in_flight: HashSet<_> = self.queries.values().copied().collect();
            let backfill: Vec<_> = self
                .remaining_authorities
                .iter()
                .filter(|a| !in_flight.contains(*a))
                .take(MAX_QUERIES - self.queries.len())
                .copied()
                .collect();

            if !backfill.is_empty() {
                self.query_dht_records(backfill);
            }
        }

        log::debug!(
            "queries: {} remaining authorities to discover {}",
            self.queries.len(),
            self.remaining_authorities.len()
        );

        self.query_peer_info();
    }

    /// Submit the DHT queries for the remaining authorities that did not receive a record yet.
    ///
    /// When the number of remaining authorities gets below a threashold (`MAX_QUERIES`),
    /// this method will also submit the `get-closest-peers` queries to force the discovery
    /// of the peers that are not reachable at the moment.
    fn resubmit_remaining_dht_queries(&mut self) {
        // Ignore older queries and finish them in Kademlia, otherwise they
        // keep running in the background and compete with the new ones.
        let stale: Vec<QueryId> = self.queries.keys().copied().collect();
        for id in stale {
            if let Some(mut query) = self.swarm.behaviour_mut().discovery.query_mut(&id) {
                query.finish();
            }
        }
        self.queries.clear();

        let authorities = self.remaining_authorities.clone();
        let mut remaining: Vec<_> = authorities.iter().collect();
        remaining.shuffle(&mut thread_rng());

        let remaining_len = remaining.len();

        log::debug!(
            " Remaining authorities: {}",
            self.remaining_authorities.len()
        );

        self.query_dht_records(remaining.into_iter().take(MAX_QUERIES).cloned());

        if remaining_len < MAX_QUERIES {
            self.query_peer_info();
        }
    }

    /// Mark that the discovery made progress towards its goal (a new record,
    /// a resolved probe dial, or a validator identify response).
    ///
    /// Kademlia background churn (random-walk queries, connections to
    /// non-validator peers) intentionally does not count as progress,
    /// otherwise the crawl would never be considered quiet.
    fn touch_progress(&mut self) {
        self.last_progress = std::time::Instant::now();
    }

    /// Whether the discovery has nothing left to do and can exit before the
    /// timeout.
    ///
    /// Once every probe dial is resolved and nothing made progress for a
    /// quiet period, waiting for the timeout only burns time. The quiet
    /// period is short when every authority record was found, and longer when
    /// records are still missing so that the periodic resubmission gets a
    /// chance to find them.
    fn discovery_finished(&self) -> bool {
        if !self.active_dials.is_empty() {
            return false;
        }

        // Addresses queued behind a live connection are never probed while
        // the connection lasts; they are finalized as skipped. A queue for a
        // disconnected peer still has probes to run.
        if !self
            .queued_dials
            .keys()
            .all(|peer| self.swarm.is_connected(peer))
        {
            return false;
        }

        let quiet_secs = if self.remaining_authorities.is_empty() {
            COMPLETE_QUIET_SECS
        } else {
            STALL_QUIET_SECS
        };
        self.last_progress.elapsed() >= std::time::Duration::from_secs(quiet_secs)
    }

    /// Record the outcome of dialing `addr`, keeping the strongest evidence
    /// gathered for it.
    ///
    /// A success is never downgraded: Kademlia keeps dialing peers throughout
    /// the crawl and a later failure (a redundant connection the remote closes,
    /// or a dial after the peer went away) does not make a working address
    /// unreachable. A skip is only recorded when nothing else is known.
    fn record_dial_outcome(&mut self, addr: Multiaddr, outcome: DialOutcome) {
        match self.dial_outcomes.get(&addr) {
            Some(DialOutcome::Success) => (),
            Some(_) if matches!(outcome, DialOutcome::Skipped(_)) => (),
            _ => {
                self.dial_outcomes.insert(addr, outcome);
            }
        }
    }

    /// Queue the addresses advertised by `peer_id` for dialing and start
    /// probing them.
    ///
    /// Addresses that cannot be reached from here are not dialed at all, so
    /// that they do not pollute the reachability numbers.
    fn queue_dials(&mut self, peer_id: PeerId, addresses: &[Multiaddr]) {
        for addr in addresses {
            if !self.dialed_addresses.insert(addr.clone()) {
                continue;
            }

            if !is_public_address(addr) {
                self.record_dial_outcome(addr.clone(), DialOutcome::Skipped("private".into()));
                continue;
            }
            if !is_dialable_transport(addr) {
                self.record_dial_outcome(
                    addr.clone(),
                    DialOutcome::Skipped("unsupported transport".into()),
                );
                continue;
            }

            self.queued_dials
                .entry(peer_id)
                .or_default()
                .push_back(addr.clone());
        }

        self.advance_peer_dial(peer_id);
    }

    /// Probe all queued addresses of `peer_id` concurrently.
    ///
    /// Substrate nodes keep a single connection per peer and close any
    /// redundant one, so the first dial that succeeds marks the remaining
    /// in-flight dials as superseded and their failures are recorded as skips
    /// rather than unreachable addresses. Dialing concurrently means a dead
    /// address no longer delays the working ones by a full connection
    /// timeout, which matters most for getting the identify response quickly.
    /// While the peer is connected its remaining addresses stay queued and are
    /// retried by [`Self::drain_queued_dials`] once the connection is gone.
    fn advance_peer_dial(&mut self, peer_id: PeerId) {
        if self.swarm.is_connected(&peer_id) {
            return;
        }

        let Some(mut queue) = self.queued_dials.remove(&peer_id) else {
            return;
        };

        while let Some(addr) = queue.pop_front() {
            let opts = DialOpts::unknown_peer_id().address(addr.clone()).build();
            let connection_id = opts.connection_id();

            match self.swarm.dial(opts) {
                Ok(()) => {
                    self.active_dials.insert(
                        connection_id,
                        ActiveDial {
                            peer: peer_id,
                            address: addr,
                            superseded: false,
                        },
                    );
                }
                Err(e) => {
                    self.record_dial_outcome(addr, DialOutcome::Failed(dial_error_message(&e)))
                }
            }
        }
    }

    /// Retry the addresses that stayed queued because their peer was connected
    /// or already had a dial in flight.
    fn drain_queued_dials(&mut self) {
        let peers: Vec<PeerId> = self.queued_dials.keys().copied().collect();
        for peer in peers {
            self.advance_peer_dial(peer);
        }
    }

    /// Account for the addresses that were never probed once the discovery is
    /// over, so that they are not mistaken for unreachable ones.
    fn finalize_queued_dials(&mut self) {
        let queued: Vec<(PeerId, VecDeque<Multiaddr>)> = self.queued_dials.drain().collect();
        for (peer, addresses) in queued {
            let reason = if self.swarm.is_connected(&peer) {
                "peer already connected"
            } else {
                "discovery ended before probing"
            };

            for addr in addresses {
                self.record_dial_outcome(addr, DialOutcome::Skipped(reason.into()));
            }
        }
    }

    /// Handle a swarm event from the p2p network.
    fn handle_swarm(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            // Discovery DHT record.
            SwarmEvent::Behaviour(behavior_event) => {
                log::trace!("Behaviour event: {:?}", behavior_event);

                match behavior_event {
                    BehaviourEvent::Discovery(KademliaEvent::OutboundQueryProgressed {
                        id,
                        result: QueryResult::GetRecord(record),
                        ..
                    }) => {
                        // Has received at least one answer for this and can advance the queries.
                        self.queries.remove(&id);

                        // The first record is enough: finish the underlying
                        // Kademlia query so it stops crawling in the
                        // background. Without this, replacement queries are
                        // submitted while the old ones still run, and the
                        // number of in-flight lookups balloons far beyond
                        // `MAX_QUERIES`, slowing every query down.
                        if let Some(mut query) = self.swarm.behaviour_mut().discovery.query_mut(&id)
                        {
                            query.finish();
                        }

                        if let Ok(GetRecordOk::FoundRecord(peer_record)) = record {
                            let key = peer_record.record.key;
                            let value = peer_record.record.value;

                            let Some(authority) = self.records_keys.get(&key) else {
                                self.advance_dht_queries();
                                return;
                            };
                            let authority = *authority;

                            let (peer_id, addresses) = match decode_dht_record(value, &authority) {
                                Ok((peer_id, addresses)) => (peer_id, addresses),
                                Err(e) => {
                                    log::debug!(
                                        " Decoding DHT failed for authority {:?}: {:?}",
                                        authority,
                                        e
                                    );
                                    self.dht_errors += 1;
                                    self.advance_dht_queries();
                                    return;
                                }
                            };

                            self.authority_to_details
                                .entry(authority)
                                .and_modify(|entry| entry.extend(addresses.clone()))
                                .or_insert_with(|| addresses.iter().cloned().collect());

                            self.peer_details
                                .entry(peer_id)
                                .and_modify(|entry| entry.addresses.extend(addresses.clone()))
                                .or_insert_with(|| PeerDetails {
                                    authority_id: authority,
                                    addresses: addresses.iter().cloned().collect(),
                                });

                            // Add addresses to Kademlia for DHT routing.
                            for addr in &addresses {
                                self.swarm
                                    .behaviour_mut()
                                    .discovery
                                    .add_address(&peer_id, addr.clone());
                            }

                            // Probe the advertised addresses through the libp2p
                            // stack (noise handshake, yamux) to test reachability
                            // per address.
                            self.queue_dials(peer_id, &addresses);

                            log::debug!(
                                "{}/{} (err {}) authority: {:?} peer_id {:?} Addresses: {:?}",
                                self.authority_to_details.len(),
                                self.authorities.len(),
                                self.dht_errors,
                                authority,
                                peer_id,
                                addresses
                            );

                            let now = std::time::Instant::now();
                            if now.duration_since(self.old_log) > std::time::Duration::from_secs(10)
                            {
                                self.old_log = now;
                                log::info!(
                                    "... DHT records {}/{} (err {}) | Identified {}/{} | Active peer queries {} | authority={:?} peer_id={:?} addresses={:?}",
                                    self.authority_to_details.len(),
                                    self.authorities.len(),
                                    self.dht_errors,

                                    self.peer_details.keys().filter_map(|peer| self.peer_info.get(peer)).count(),
                                    self.peer_details.keys().count(),

                                    self.queries_discovery.len(),

                                    authority,
                                    peer_id,
                                    addresses
                                );
                            }

                            if self.remaining_authorities.remove(&authority) {
                                self.touch_progress();
                            }
                        } else {
                            log::debug!(
                                "DHT query failed: {:?} (in-flight: {}, remaining: {})",
                                record.err(),
                                self.queries.len(),
                                self.remaining_authorities.len()
                            );
                        }

                        // Always advance queries regardless of success or failure,
                        // otherwise failed queries reduce concurrency without replacement
                        // and the discovery stalls until the resubmit timer fires.
                        self.advance_dht_queries();
                    }

                    BehaviourEvent::Discovery(KademliaEvent::OutboundQueryProgressed {
                        id,
                        result: QueryResult::GetClosestPeers(_),
                        ..
                    }) => {
                        if self.finished_query {
                            log::debug!(" Discovered closes peers of {:?}", id);
                        }

                        self.queries_discovery.remove(&id);
                        self.query_peer_info();
                    }

                    BehaviourEvent::PeerInfo(info_event) => {
                        match info_event {
                            PeerInfoEvent::Identified { peer_id, info } => {
                                if self.finished_query {
                                    let discovered = self
                                        .peer_details
                                        .keys()
                                        .filter_map(|peer| self.peer_info.get(peer))
                                        .count();

                                    log::debug!(
                                        " {}/{} Info event {:?}",
                                        discovered,
                                        self.authorities.len(),
                                        peer_id
                                    );
                                }

                                // A validator identify response is the goal of
                                // the whole crawl, so it counts as progress.
                                // Identifies of random network peers do not:
                                // they arrive for as long as Kademlia crawls.
                                if self.peer_details.contains_key(&peer_id)
                                    && !self.peer_info.contains_key(&peer_id)
                                {
                                    self.touch_progress();
                                }

                                // Save the record.
                                self.peer_info.insert(peer_id, info);
                            }
                        };
                    }
                    _ => (),
                }
            }

            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                endpoint,
                num_established,
                ..
            } => {
                log::trace!(
                    "Connection closed: peer_id={:?} connection_id={:?} endpoint={:?} num_established={:?}",
                    peer_id,
                    connection_id,
                    endpoint,
                    num_established,
                );
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                num_established,
                ..
            } => {
                self.reached_peers.insert(peer_id);

                // The address that carried the connection is reachable, no
                // matter who started the dial: Kademlia opens connections of
                // its own during the crawl and they prove the same thing.
                if let ConnectedPoint::Dialer { ref address, .. } = endpoint {
                    self.record_dial_outcome(address.clone(), DialOutcome::Success);
                }

                if let Some(dial) = self.active_dials.remove(&connection_id) {
                    self.record_dial_outcome(dial.address, DialOutcome::Success);
                    self.touch_progress();
                }

                // A fresh connection to a not-yet-identified validator will
                // produce an identify response shortly; hold the early exit
                // until it lands. This also covers connections Kademlia opened
                // on its own.
                if self.peer_details.contains_key(&peer_id)
                    && !self.peer_info.contains_key(&peer_id)
                {
                    self.touch_progress();
                }

                // Any other dial to this peer that is still in flight can only
                // fail now, since the remote closes redundant connections. The
                // addresses that are still queued keep waiting for the
                // connection to go away.
                for dial in self.active_dials.values_mut() {
                    if dial.peer == peer_id {
                        dial.superseded = true;
                    }
                }

                log::trace!(
                    "Connection established: peer_id={:?} connection_id={:?} endpoint={:?} num_established={:?}",
                    peer_id,
                    connection_id,
                    endpoint,
                    num_established,
                );
            }

            SwarmEvent::Dialing {
                peer_id,
                connection_id,
            } => {
                log::trace!(
                    "Dialing: peer_id={:?} connection_id={:?}",
                    peer_id,
                    connection_id,
                );
            }

            SwarmEvent::OutgoingConnectionError {
                connection_id,
                peer_id,
                error,
            } => {
                // Only our own dials say something about a specific address.
                // Kademlia dials the same peers over and over during the crawl
                // and its failures must not overwrite what we learned.
                if let Some(dial) = self.active_dials.remove(&connection_id) {
                    let outcome = if dial.superseded {
                        DialOutcome::Skipped("peer already connected".into())
                    } else {
                        DialOutcome::Failed(dial_error_message(&error))
                    };
                    self.record_dial_outcome(dial.address, outcome);
                    self.advance_peer_dial(dial.peer);
                    self.touch_progress();
                }

                log::trace!(
                    "Outgoing connection error: peer_id={:?} connection_id={:?} error={:?}",
                    peer_id,
                    connection_id,
                    error,
                );
            }

            SwarmEvent::IncomingConnectionError {
                connection_id,
                local_addr,
                send_back_addr,
                error,
                ..
            } => {
                log::trace!(
                    "Incoming connection error: connection_id={:?} local_addr={:?} send_back_addr={:?} error={:?}",
                    connection_id,
                    local_addr,
                    send_back_addr,
                    error,
                );
            }

            _ => (),
        }
    }

    /// Enable or disable interactive progress bar output on stdout.
    pub fn set_show_progress(&mut self, show: bool) {
        self.show_progress = show;
    }

    /// Print an in-place progress bar to stdout.
    fn print_progress(&self) {
        let elapsed = self.start_time.elapsed().as_secs();
        let total = self.authorities.len();
        let found = self.authority_to_details.len();
        let identified = self
            .peer_details
            .keys()
            .filter(|peer| self.peer_info.contains_key(peer))
            .count();

        let pct = if total > 0 {
            found as f64 / total as f64
        } else {
            0.0
        };
        let bar_width = 25;
        let filled = (pct * bar_width as f64) as usize;
        let bar = format!(
            "{}{}",
            "\u{2588}".repeat(filled),
            "\u{2591}".repeat(bar_width - filled)
        );

        let connected_peers = self.swarm.connected_peers().count();
        let queries_inflight = self.queries.len();
        // Restricted to the advertised addresses: the outcome map also holds
        // the connections Kademlia opened to the rest of the network.
        let (dial_ok, dial_fail) = self
            .dialed_addresses
            .iter()
            .fold((0, 0), |(ok, fail), addr| {
                match self.dial_outcomes.get(addr) {
                    Some(DialOutcome::Success) => (ok + 1, fail),
                    Some(DialOutcome::Failed(_)) => (ok, fail + 1),
                    _ => (ok, fail),
                }
            });

        print!(
            "\r       [{}] {}/{} ({:.1}%) | Id: {} | Dials: {}/{} ok | Err: {} | Peers: {} | Q: {} | {}s/{}s   ",
            bar,
            found,
            total,
            pct * 100.0,
            identified,
            dial_ok,
            dial_ok + dial_fail,
            self.dht_errors,
            connected_peers,
            queries_inflight,
            elapsed,
            self.timeout_secs,
        );
        let _ = std::io::stdout().flush();
    }

    /// Run the discovery process.
    pub async fn discover(&mut self) {
        self.advance_dht_queries();
        self.start_time = std::time::Instant::now();
        self.last_progress = std::time::Instant::now();

        // Should return immediately.
        self.interval_resubmit.tick().await;
        self.interval_exit.tick().await;

        let mut progress_interval = tokio::time::interval(std::time::Duration::from_secs(1));
        progress_interval.tick().await;

        loop {
            futures::select! {
                event = self.swarm.select_next_some().fuse() => {
                    self.handle_swarm(event);
                },

                _ = self.interval_resubmit.tick().fuse() => {
                    self.resubmit_remaining_dht_queries();
                    self.drain_queued_dials();
                }

                _ = progress_interval.tick().fuse() => {
                    if self.show_progress {
                        self.print_progress();
                    }

                    if self.discovery_finished() {
                        if self.show_progress {
                            // Clear the progress line.
                            print!("\r{}\r", " ".repeat(100));
                            let _ = std::io::stdout().flush();
                        }

                        if self.remaining_authorities.is_empty() {
                            log::info!(
                                "All authorities discovered and probed, exiting early after {}s",
                                self.start_time.elapsed().as_secs()
                            );
                        } else {
                            log::info!(
                                "No progress for {}s with {} authorities still missing, exiting early after {}s",
                                STALL_QUIET_SECS,
                                self.remaining_authorities.len(),
                                self.start_time.elapsed().as_secs()
                            );
                        }

                        return;
                    }
                }

                _ = self.interval_exit.tick().fuse() => {
                    if self.show_progress {
                        // Clear the progress line.
                        print!("\r{}\r", " ".repeat(100));
                        let _ = std::io::stdout().flush();
                    }

                    if self.authority_to_details.len() == self.authorities.len() {
                        log::info!("All authorities discovered from DHT");
                    } else {
                        log::info!("Exiting due to timeout");
                    }

                    return;
                }
            }
        }
    }

    /// Returns a reference to the discovered peer details.
    #[allow(dead_code)]
    pub fn peer_details(&self) -> &HashMap<PeerId, PeerDetails> {
        &self.peer_details
    }

    /// Returns a reference to the discovered peer info.
    #[allow(dead_code)]
    pub fn peer_info(&self) -> &HashMap<PeerId, Info> {
        &self.peer_info
    }

    /// Returns a reference to the mapping between the authority discovery public key and the
    /// discovered addresses.
    #[allow(dead_code)]
    pub fn authority_to_details(&self) -> &HashMap<sr25519::PublicKey, HashSet<Multiaddr>> {
        &self.authority_to_details
    }

    /// Consume the discovery state and return the collected results.
    ///
    /// This drops the underlying swarm, freeing its network connections and
    /// file descriptors so that subsequent phases (e.g. TCP reachability
    /// checks) do not hit the open-file limit.
    pub fn into_results(
        mut self,
    ) -> (
        HashMap<sr25519::PublicKey, HashSet<Multiaddr>>,
        HashMap<PeerId, Info>,
        HashMap<Multiaddr, DialOutcome>,
        HashSet<PeerId>,
    ) {
        self.finalize_queued_dials();

        (
            self.authority_to_details,
            self.peer_info,
            self.dial_outcomes,
            self.reached_peers,
        )
    }
}

/// Reach a single peer and query the identify protocol.
///
/// # Example
///
/// The following address is taken from the DHT.
/// However, the address cannot be reached directly.
/// For this to work, we'd need to implement NAT hole punching.
///
/// ```ignore
/// let addr =
///     "/ip4/34.92.86.244/tcp/40333/p2p/12D3KooWKxsprneVYQxxPnPUwDA5p2huuCbZCNyuSHTmKDv3vT2n";
/// let addr: Multiaddr = addr.parse().expect("Valid multiaddress; qed");
/// let peer_id = get_peer_id(&addr);
/// let info = PeerInfo::new(local_key.clone(), vec![addr]);
/// let info = info.discover().await;
/// println!("Peer={:?} version={:?}", peer_id, info);
/// ```
#[allow(dead_code)]
struct PeerInfo {
    swarm: Swarm<libp2p::identify::Behaviour>,
}

#[allow(dead_code)]
impl PeerInfo {
    pub async fn new(local_key: libp2p::identity::Keypair, addresses: Vec<Multiaddr>) -> Self {
        let identify_config =
            libp2p::identify::Config::new("/substrate/1.0".to_string(), local_key.public())
                .with_agent_version("subp2p-identify".to_string())
                .with_cache_size(0);
        let identify = libp2p::identify::Behaviour::new(identify_config);

        let tcp_config = libp2p::tcp::Config::new().nodelay(true);
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp_config,
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .expect("Can construct TCP; qed")
            .with_dns()
            .expect("Can construct DNS; qed")
            .with_websocket(libp2p::noise::Config::new, libp2p::yamux::Config::default)
            .await
            .expect("Can construct WebSocket; qed")
            .with_behaviour(|_key| identify)
            .expect("Can construct behaviour; qed")
            .build();

        for multiaddress in &addresses {
            let _ = swarm.dial(multiaddress.clone());
        }

        PeerInfo { swarm }
    }

    pub async fn discover(mut self) -> Result<Info, libp2p::swarm::DialError> {
        loop {
            let event = self.swarm.select_next_some().await;

            match event {
                SwarmEvent::Behaviour(libp2p::identify::Event::Received { info, .. }) => {
                    return Ok(info);
                }

                SwarmEvent::OutgoingConnectionError { error, .. } => return Err(error),

                _ => (),
            }
        }
    }
}

/// Entry function called from the CLI.
pub async fn discover_authorities(
    url: String,
    genesis: String,
    bootnodes: Vec<String>,
    timeout: std::time::Duration,
    address_format: String,
    raw_output: bool,
    query_timeout: std::time::Duration,
) -> Result<(AuthorityDiscovery, Vec<sr25519::PublicKey>), Box<dyn std::error::Error>> {
    let format_registry =
        ss58_registry::Ss58AddressFormatRegistry::try_from(address_format.as_str())
            .map_err(|err| format!("Cannot parse the provided address format: {:?}", err))?;
    let version: ss58_registry::Ss58AddressFormat = format_registry.into();
    let version = version.prefix();
    log::info!(
        "Address format {:?} with version prefix {:?}",
        format_registry,
        version
    );

    let url = Url::parse(&url)?;

    // Extract the authorities from the runtime API.
    let authorities = runtime_api_autorities(url).await?;

    // Perform DHT queries to find the authorities on the network.
    // Then, record the addresses of the authorities and the responses
    // from the identify protocol.
    let swarm = build_swarm(genesis.clone(), bootnodes, query_timeout).await?;
    let mut authority_discovery = AuthorityDiscovery::new(swarm, authorities.clone(), timeout);
    authority_discovery.discover().await;
    log::info!("Finished discovery\n");

    let mut reached_peers = 0;
    let mut litep2p = 0;

    for authority in &authorities {
        let Some(details) = authority_discovery.authority_to_details.get(authority) else {
            println!(
                "authority={:?} - No dht response",
                to_ss58(authority, version),
            );
            continue;
        };

        let Some(addr) = details.iter().next() else {
            println!(
                "authority={:?} - No addresses found in DHT record",
                to_ss58(authority, version),
            );
            continue;
        };

        let peer_id = get_peer_id(addr).expect("All must have valid peerIDs");

        let info = authority_discovery.peer_info.get(&peer_id).cloned();
        if let Some(info) = info {
            reached_peers += 1;

            if info.agent_version.contains("litep2p") {
                litep2p += 1;
            }

            println!(
                "authority={:?} peer_id={:?} addresses={:?} version={:?} ",
                to_ss58(authority, version),
                peer_id,
                info.agent_version,
                details,
            );
        } else {
            println!(
                "authority={:?} peer_id={:?} addresses={:?} - Cannot be reached",
                to_ss58(authority, version),
                peer_id,
                details,
            );
        }
    }

    println!(
        "\n\n  Discovered {}/{} authorities",
        reached_peers,
        authorities.len()
    );

    println!(" Discovered peers {}", authority_discovery.peer_info.len());

    if raw_output {
        println!("\n Raw output of the discovered peers:");

        for (peer_id, info) in &authority_discovery.peer_info {
            println!("peer_id={:?} info={:?}", peer_id, info);
        }
    }

    println!(" Litep2p authorities {}", litep2p);

    Ok((authority_discovery, authorities))
}
