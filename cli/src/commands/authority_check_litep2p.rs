// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

//! Authority discovery on top of the litep2p network backend.
//!
//! This is the litep2p counterpart of `AuthorityDiscovery` from the
//! `authorities` module, selected with `authority-check --network-backend
//! litep2p`. It runs the same crawl (a Kademlia `get-record` for every
//! authority, dial probes for every advertised address, targeted lookups for
//! validators that could not be reached) and hands back the same results, so
//! the `authority-check` report is shared between the two network stacks.
//!
//! The libp2p implementation is deliberately left untouched. The two stacks
//! differ enough in their dial semantics that mirroring the crawl is clearer
//! than abstracting over them:
//!
//! - litep2p keeps a single dial in flight per peer. Dialing a peer that is
//!   already being dialed is accepted and silently dropped, so the standard
//!   crawl probes the addresses of a peer one after the other and the
//!   aggressive one hands litep2p all of them at once with `dial(peer)`.
//! - Dial results are reported per address, not per connection id, and the
//!   failures of Kademlia's own dials arrive through the same events. The
//!   address of an established connection is rebuilt from the socket, so it
//!   lacks the `/p2p/<peer>` suffix carried by the DHT record addresses.
//! - Queries cannot be cancelled, so the query timeout is enforced here by
//!   forgetting about a query once it ran for too long.
//!
//! Unlike the libp2p crawl, this one does not stop when it goes quiet: as long
//! as a record is missing or a validator did not answer identify, the crawl
//! keeps re-querying, re-probing and re-looking-up until the timeout. It exits
//! early only once every record was found and every validator identified.
//!
//! # Aggressive mode
//!
//! `--aggressive` trades politeness for speed, see [`Tuning::aggressive`]:
//! every authority record is queried at once as soon as the routing table
//! holds a few dozen peers, the table is seeded with the peers of the previous
//! run and the validators of that run are dialed before their records arrive,
//! the addresses of a validator are raced until it answers identify (the
//! losers are probed one at a time afterwards), connections stay open
//! across hops, and dead addresses and slow queries are given up on sooner.

use crate::commands::authorities::{DialOutcome, COMPLETE_QUIET_SECS, MAX_LOOKUPS, MAX_QUERIES};
use crate::commands::authority_check::{DiscoveryResults, IdentifyInfo};
use crate::commands::peer_cache::PeerCache;
use crate::utils::{is_dialable_transport, is_public_address, with_peer_id, without_peer_id};
use futures::{Stream, StreamExt};
use libp2p::{Multiaddr, PeerId};
use litep2p::{
    config::ConfigBuilder,
    crypto::ed25519::Keypair,
    protocol::libp2p::{
        identify::{Config as IdentifyConfig, IdentifyEvent},
        kademlia::{
            ConfigBuilder as KademliaConfigBuilder, KademliaEvent, KademliaHandle, PeerRecord,
            QueryId, Quorum, RecordKey, RoutingTableUpdateMode,
        },
        ping::{Config as PingConfig, PingEvent},
    },
    transport::{
        tcp::config::Config as TcpConfig, websocket::config::Config as WebSocketConfig, Endpoint,
    },
    types::ConnectionId,
    Litep2p, Litep2pEvent, PeerId as Litep2pPeerId, ProtocolName,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::io::Write;
use std::time::{Duration, Instant};
use subp2p_explorer::{
    peer_behavior::AGENT,
    util::authorities::{decode_dht_record, hash_authority_id},
    util::crypto::sr25519,
    util::p2p::get_peer_id,
};

/// Number of times a dropped probe is issued again before giving up on it.
const MAX_DIAL_ATTEMPTS: u8 = 3;

/// Validators that did not answer identify have their advertised addresses
/// probed again this often. A node may have been restarting, and a later
/// success upgrades the recorded outcome of an address.
const RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// A validator whose addresses were all probed without an identify response is
/// looked up in the DHT again this often.
const LOOKUP_RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// Cached validators dialed at once before their records arrive. Each dial
/// races all known addresses of the validator.
const MAX_WARM_DIALS: usize = 512;

/// Routing table size at which the aggressive crawl stops holding back its
/// record queries. Below it every query would start at the bootnodes.
const RAMP_ROUTING_PEERS: usize = 64;

/// How the crawl treats the network.
#[derive(Clone, Copy, Debug)]
struct Tuning {
    /// Cap on concurrent `get-record` queries once the routing table holds
    /// `ramp_routing_peers` peers. Below that the standard cap applies.
    max_queries: usize,
    /// See `max_queries`.
    ramp_routing_peers: usize,
    /// Dial timeout of the transports. Every dial that reaches the network
    /// resolves within this time, with a connection or with a failure.
    connection_open_timeout: Duration,
    /// Idle time before a connection without substreams is closed.
    keep_alive_timeout: Duration,
    /// Addresses of one peer dialed at once by `dial(peer)`.
    max_parallel_dials: usize,
    /// Race all addresses of a peer that did not answer identify yet, instead
    /// of probing them one after the other.
    parallel_probes: bool,
    /// Upper bound on the query timeout given on the command line.
    max_query_timeout: Option<Duration>,
}

impl Tuning {
    /// litep2p defaults, one probe per peer at a time.
    fn standard() -> Self {
        Tuning {
            max_queries: MAX_QUERIES,
            ramp_routing_peers: 0,
            connection_open_timeout: Duration::from_secs(10),
            keep_alive_timeout: Duration::from_secs(5),
            max_parallel_dials: 8,
            parallel_probes: false,
            max_query_timeout: None,
        }
    }

    /// As hard as the network allows.
    ///
    /// Per-query parallelism is fixed at three inside litep2p, so speed comes
    /// from running every query at once. A dead peer on the path holds one of
    /// a query's three slots for the whole dial timeout, hence the shorter
    /// timeouts. Hops keep re-contacting the same DHT nodes, hence the longer
    /// keep-alive: a reused connection saves a TCP, noise and yamux handshake.
    /// It is not longer still because the addresses that lost a race can only
    /// be probed once the winning connection is gone.
    fn aggressive() -> Self {
        Tuning {
            max_queries: usize::MAX,
            ramp_routing_peers: RAMP_ROUTING_PEERS,
            connection_open_timeout: Duration::from_secs(5),
            keep_alive_timeout: Duration::from_secs(15),
            max_parallel_dials: 16,
            parallel_probes: true,
            max_query_timeout: Some(Duration::from_secs(6)),
        }
    }

    /// A probe that did not resolve within this time never reached the
    /// network: litep2p dropped it because Kademlia was already dialing the
    /// same peer.
    fn dial_stall_timeout(&self) -> Duration {
        self.connection_open_timeout * 2
    }
}

/// How to run the litep2p crawl.
#[derive(Default)]
pub struct Litep2pOptions {
    /// Use the aggressive tuning.
    pub aggressive: bool,
    /// Peers of a previous run, to start warm. Only read in aggressive mode.
    pub peer_cache: Option<PeerCache>,
}

type IdentifyStream = Box<dyn Stream<Item = IdentifyEvent> + Send + Unpin>;
type PingStream = Box<dyn Stream<Item = PingEvent> + Send + Unpin>;

/// A probe of the advertised addresses of a peer.
#[derive(Debug)]
struct ActiveDial {
    /// Addresses being probed and not resolved yet: a single one, or all of
    /// them when `race` is set.
    addresses: Vec<Multiaddr>,
    /// Whether the addresses were handed to litep2p at once with `dial(peer)`,
    /// or the single address with `dial_address`.
    race: bool,
    /// When the current attempt was issued.
    started: Instant,
    /// Number of times the probe was issued, see [`Tuning::dial_stall_timeout`].
    attempts: u8,
}

/// Something the crawl has to react to.
enum Event {
    Network(Option<Litep2pEvent>),
    Kademlia(Option<KademliaEvent>),
    Identify(Option<IdentifyEvent>),
    Ping(Option<PingEvent>),
    Resubmit,
    Retry,
    Progress,
    Exit,
}

/// Discover the authorities on the network with litep2p.
pub struct Litep2pAuthorityDiscovery {
    /// Drive the network stack.
    litep2p: Litep2p,
    /// Kademlia commands and events.
    kademlia: KademliaHandle,
    /// Identify responses.
    identify: IdentifyStream,
    /// Ping events. Never acted upon, only drained so that the protocol keeps
    /// making progress.
    ping: PingStream,
    /// Knobs of this crawl.
    tuning: Tuning,

    /// In flight `get-record` queries, with the time they were submitted, to
    /// bound how many run and expire the slow ones.
    queries: HashMap<QueryId, (sr25519::PublicKey, Instant)>,
    /// In flight `find-node` lookups for validators that were not reached at
    /// their advertised addresses.
    queries_discovery: HashMap<QueryId, (PeerId, Instant)>,
    /// Peers known to the Kademlia routing table, from the seed and from the
    /// routing table updates. Drives the query ramp.
    routing_peers: HashSet<PeerId>,

    /// Map the record keys to the authority ids.
    records_keys: HashMap<Vec<u8>, sr25519::PublicKey>,
    /// Addresses of the validators, from the DHT records.
    peer_details: HashMap<PeerId, HashSet<Multiaddr>>,
    /// Identify responses of every peer reached.
    peer_info: HashMap<PeerId, IdentifyInfo>,
    authority_to_details: HashMap<sr25519::PublicKey, HashSet<Multiaddr>>,

    /// Initially provided authority list.
    authorities: Vec<sr25519::PublicKey>,
    /// Query index.
    query_index: usize,

    /// Encountered DHT errors, either from decoding or protocol transport.
    dht_errors: usize,

    /// Remaining authorities to query.
    remaining_authorities: HashSet<sr25519::PublicKey>,
    /// A query or lookup older than this is considered failed.
    query_timeout: Duration,

    /// Time of the last log line.
    old_log: Instant,
    /// Time of the last discovery progress, see `touch_progress`.
    last_progress: Instant,
    /// Interval at which to resubmit the remaining queries.
    interval_resubmit: tokio::time::Interval,
    /// Interval at which to bail out.
    interval_exit: tokio::time::Interval,
    /// Interval at which unidentified validators are probed again.
    interval_retry: tokio::time::Interval,

    /// Whether to print an interactive progress bar to stdout.
    show_progress: bool,
    /// When the discovery process started.
    start_time: Instant,
    /// Timeout duration for display purposes.
    timeout_secs: u64,

    /// Per-address dial outcomes (noise + yamux upgrade).
    dial_outcomes: HashMap<Multiaddr, DialOutcome>,
    /// Addresses already queued for dialing. Deduplicates addresses advertised
    /// by more than one authority record, or already probed from the cache.
    dialed_addresses: HashSet<Multiaddr>,
    /// Addresses waiting to be dialed, per peer.
    queued_dials: HashMap<PeerId, VecDeque<Multiaddr>>,
    /// The probe currently running for each peer. litep2p runs a single dial
    /// per peer, so there is at most one.
    active_dials: HashMap<PeerId, ActiveDial>,
    /// Open connections per peer.
    connections: HashMap<PeerId, HashSet<ConnectionId>>,

    /// Validators of the previous run waiting to be dialed before their record
    /// arrives, with their cached addresses.
    warm_dials: VecDeque<(PeerId, Vec<Multiaddr>)>,
    /// Number of cached validators dialed so far.
    warm_dialed: usize,

    /// Every distinct peer a connection was established with during the crawl,
    /// validators and regular network nodes alike.
    reached_peers: HashSet<PeerId>,

    /// Validators whose advertised addresses were all probed without an
    /// identify response, waiting for a lookup slot.
    pending_lookups: VecDeque<PeerId>,
    /// When each validator was last queued for a targeted lookup.
    last_lookup: HashMap<PeerId, Instant>,
}

/// Convert a libp2p peer ID into its litep2p counterpart. Multiaddresses need
/// no conversion: both stacks use the same `multiaddr` crate.
fn to_litep2p_peer(peer: &PeerId) -> Option<Litep2pPeerId> {
    Litep2pPeerId::from_bytes(&peer.to_bytes()).ok()
}

/// Convert a litep2p peer ID into its libp2p counterpart.
fn from_litep2p_peer(peer: &Litep2pPeerId) -> Option<PeerId> {
    PeerId::from_bytes(&peer.to_bytes()).ok()
}

/// Split a bootnode string into the peer and the address.
fn parse_bootnode(bootnode: &str) -> Option<(Litep2pPeerId, Multiaddr)> {
    let address: Multiaddr = bootnode.parse().ok()?;
    let peer = Litep2pPeerId::try_from_multiaddr(&address)?;
    Some((peer, address))
}

/// Whether the crawler can and should dial this address at all.
fn is_probe_candidate(address: &Multiaddr) -> bool {
    is_public_address(address) && is_dialable_transport(address)
}

impl Litep2pAuthorityDiscovery {
    /// Constructs a new [`Litep2pAuthorityDiscovery`].
    ///
    /// Builds the litep2p stack with the same protocols as the libp2p swarm:
    /// TCP and WebSocket transports, ping, identify and the chain-specific
    /// Kademlia protocol seeded with the bootnodes (and, in aggressive mode,
    /// with the cached peers). No notification protocol is registered, so
    /// connections close once they go idle instead of holding a slot on both
    /// sides until the crawl ends.
    pub fn new(
        genesis: &str,
        bootnodes: Vec<String>,
        authorities: Vec<sr25519::PublicKey>,
        timeout: Duration,
        query_timeout: Duration,
        options: Litep2pOptions,
    ) -> Result<Self, Box<dyn Error>> {
        let genesis = genesis.trim_start_matches("0x");
        let tuning = if options.aggressive {
            Tuning::aggressive()
        } else {
            Tuning::standard()
        };
        let query_timeout = match tuning.max_query_timeout {
            Some(cap) => query_timeout.min(cap),
            None => query_timeout,
        };

        let mut known_peers: HashMap<Litep2pPeerId, Vec<Multiaddr>> =
            bootnodes
                .iter()
                .fold(HashMap::new(), |mut peers, bootnode| {
                    match parse_bootnode(bootnode) {
                        Some((peer, address)) => {
                            log::info!("Bootnode peer={:?}", peer);
                            peers.entry(peer).or_default().push(address);
                        }
                        None => log::warn!("Ignoring invalid bootnode {}", bootnode),
                    }
                    peers
                });

        // Warm start: every cached peer goes into the routing table, so the
        // queries start next to their keys, and the cached validators are
        // dialed right away.
        let mut routing_peers = HashSet::new();
        let mut warm_dials = VecDeque::new();
        if let Some(cache) = options.peer_cache.filter(|_| options.aggressive) {
            for (peer, addresses) in cache.known_peers() {
                if let Some(lite) = to_litep2p_peer(&peer) {
                    known_peers.entry(lite).or_default().extend(addresses);
                    routing_peers.insert(peer);
                }
            }
            warm_dials.extend(cache.validators());
            log::info!(
                "Warm start with {} cached peers, {} validators to dial",
                routing_peers.len(),
                warm_dials.len()
            );
        }

        let (ping_config, ping) = PingConfig::default();
        let (kademlia_config, kademlia) = KademliaConfigBuilder::new()
            .with_protocol_names(vec![ProtocolName::from(format!("/{genesis}/kad"))])
            .with_routing_table_update_mode(RoutingTableUpdateMode::Automatic)
            .with_known_peers(known_peers.clone())
            .build();
        let (identify_config, identify) =
            IdentifyConfig::new("/substrate/1.0".to_string(), Some(AGENT.to_string()));

        // No listen addresses: the crawler only dials out, like the libp2p
        // swarm, so nobody can push connections onto it.
        let config = ConfigBuilder::new()
            .with_keypair(Keypair::generate())
            .with_tcp(TcpConfig {
                listen_addresses: Vec::new(),
                nodelay: true,
                connection_open_timeout: tuning.connection_open_timeout,
                ..Default::default()
            })
            .with_websocket(WebSocketConfig {
                listen_addresses: Vec::new(),
                nodelay: true,
                connection_open_timeout: tuning.connection_open_timeout,
                ..Default::default()
            })
            .with_max_parallel_dials(tuning.max_parallel_dials)
            .with_keep_alive_timeout(tuning.keep_alive_timeout)
            .with_libp2p_ping(ping_config)
            .with_libp2p_kademlia(kademlia_config)
            .with_libp2p_identify(identify_config)
            .build();

        let mut litep2p = Litep2p::new(config)?;
        tracing::info!("Local peer ID {:?}", litep2p.local_peer_id());

        for (peer, addresses) in known_peers {
            litep2p.add_known_address(peer, addresses.into_iter());
        }

        Ok(Litep2pAuthorityDiscovery {
            litep2p,
            kademlia,
            identify,
            ping,
            tuning,

            queries: HashMap::with_capacity(1024),
            queries_discovery: HashMap::with_capacity(MAX_LOOKUPS),
            routing_peers,

            records_keys: HashMap::with_capacity(1024),
            peer_details: HashMap::with_capacity(1024),
            peer_info: HashMap::with_capacity(1024),
            authority_to_details: HashMap::with_capacity(1024),

            authorities: authorities.clone(),
            query_index: 0,

            dht_errors: 0,

            remaining_authorities: authorities.into_iter().collect(),
            query_timeout,

            old_log: Instant::now(),
            last_progress: Instant::now(),
            interval_resubmit: tokio::time::interval(Duration::from_secs(15)),
            interval_exit: tokio::time::interval(timeout),
            interval_retry: tokio::time::interval(RETRY_INTERVAL),

            show_progress: false,
            start_time: Instant::now(),
            timeout_secs: timeout.as_secs(),

            dial_outcomes: HashMap::with_capacity(4096),
            dialed_addresses: HashSet::with_capacity(4096),
            queued_dials: HashMap::with_capacity(1024),
            active_dials: HashMap::with_capacity(1024),
            connections: HashMap::with_capacity(1024),

            warm_dials,
            warm_dialed: 0,

            reached_peers: HashSet::with_capacity(4096),

            pending_lookups: VecDeque::new(),
            last_lookup: HashMap::with_capacity(256),
        })
    }

    /// Enable or disable interactive progress bar output on stdout.
    pub fn set_show_progress(&mut self, show: bool) {
        self.show_progress = show;
    }

    /// Whether at least one connection to `peer` is open.
    fn is_connected(&self, peer: &PeerId) -> bool {
        self.connections
            .get(peer)
            .is_some_and(|connections| !connections.is_empty())
    }

    /// Whether `peer` is a validator we have no identify response from yet.
    fn is_unidentified_validator(&self, peer: &PeerId) -> bool {
        self.peer_details.contains_key(peer) && !self.peer_info.contains_key(peer)
    }

    /// Whether a probe of ours for `peer` is still running or queued.
    fn has_pending_probes(&self, peer: &PeerId) -> bool {
        self.active_dials.contains_key(peer)
            || self
                .queued_dials
                .get(peer)
                .is_some_and(|queue| !queue.is_empty())
    }

    /// Mark that the discovery made progress towards its goal (a new record,
    /// a resolved probe dial, or a validator identify response).
    ///
    /// Kademlia background churn (connections to non-validator peers)
    /// intentionally does not count as progress, otherwise the crawl would
    /// never be considered quiet.
    fn touch_progress(&mut self) {
        self.last_progress = Instant::now();
    }

    /// Concurrent record queries allowed right now.
    fn query_cap(&self) -> usize {
        if self.routing_peers.len() >= self.tuning.ramp_routing_peers {
            self.tuning.max_queries
        } else {
            MAX_QUERIES
        }
    }

    /// Query the DHT for the records of the authorities.
    async fn query_dht_records(
        &mut self,
        authorities: impl IntoIterator<Item = sr25519::PublicKey>,
    ) {
        for authority in authorities {
            let key = hash_authority_id(&authority).to_vec();
            self.records_keys.insert(key.clone(), authority);

            let id = self
                .kademlia
                .get_record(RecordKey::from(key), Quorum::One)
                .await;
            self.queries.insert(id, (authority, Instant::now()));
        }
    }

    /// Submit DHT queries to find authority records, up to the current cap.
    ///
    /// After one query is submitted for every authority this method backfills
    /// the free slots with the authorities whose record was not found yet.
    async fn advance_dht_queries(&mut self) {
        let cap = self.query_cap();

        while self.queries.len() < cap {
            if let Some(next) = self.authorities.get(self.query_index) {
                self.query_dht_records(std::iter::once(*next)).await;
                self.query_index += 1;
            } else {
                break;
            }
        }

        if self.query_index >= self.authorities.len() && self.queries.len() < cap {
            let in_flight: HashSet<_> = self
                .queries
                .values()
                .map(|(authority, _)| *authority)
                .collect();
            let backfill: Vec<_> = self
                .remaining_authorities
                .iter()
                .filter(|a| !in_flight.contains(*a))
                .take(cap - self.queries.len())
                .copied()
                .collect();

            if !backfill.is_empty() {
                self.query_dht_records(backfill).await;
            }
        }

        log::debug!(
            "queries: {} (cap {}) remaining authorities to discover {}",
            self.queries.len(),
            cap,
            self.remaining_authorities.len()
        );

        self.advance_peer_lookups().await;
    }

    /// Forget about the queries and lookups that ran for longer than the query
    /// timeout, so that their slots are reused.
    ///
    /// litep2p cannot cancel a query: the lookup keeps running in the
    /// background and a late record still lands, since records are matched by
    /// key rather than by query id.
    fn expire_stale_queries(&mut self) {
        let timeout = self.query_timeout;

        let before = self.queries.len();
        self.queries
            .retain(|_, (_, started)| started.elapsed() < timeout);
        let expired = before - self.queries.len();
        if expired > 0 {
            log::debug!(
                "Expired {} DHT queries after {}s (remaining: {})",
                expired,
                timeout.as_secs(),
                self.remaining_authorities.len()
            );
        }

        let before = self.queries_discovery.len();
        self.queries_discovery
            .retain(|_, (_, started)| started.elapsed() < timeout);
        let expired = before - self.queries_discovery.len();
        if expired > 0 {
            log::debug!("Expired {} validator lookups", expired);
        }
    }

    /// Start the queued lookups, at most [`MAX_LOOKUPS`] at a time.
    async fn advance_peer_lookups(&mut self) {
        while self.queries_discovery.len() < MAX_LOOKUPS {
            let Some(peer) = self.pending_lookups.pop_front() else {
                break;
            };
            let Some(target) = to_litep2p_peer(&peer) else {
                continue;
            };
            let id = self.kademlia.find_node(target).await;
            self.queries_discovery.insert(id, (peer, Instant::now()));
        }
    }

    /// Called once no probe is left for `peer`: every advertised address was
    /// dialed or skipped and the validator still did not answer identify.
    ///
    /// A lookup for the validator's own peer ID walks to its DHT neighbours,
    /// which hold the addresses they observed it on, and Kademlia dials the
    /// validator with everything learned on the way. See the libp2p
    /// implementation for the full reasoning. The lookup is repeated every
    /// [`LOOKUP_RETRY_INTERVAL`] for as long as the validator stays silent.
    async fn on_probes_exhausted(&mut self, peer: PeerId) {
        if self.is_connected(&peer)
            || !self.is_unidentified_validator(&peer)
            || self.has_pending_probes(&peer)
            || self.pending_lookups.contains(&peer)
        {
            return;
        }

        let due = self
            .last_lookup
            .get(&peer)
            .is_none_or(|at| at.elapsed() >= LOOKUP_RETRY_INTERVAL);
        if due {
            self.last_lookup.insert(peer, Instant::now());
            self.pending_lookups.push_back(peer);
            self.advance_peer_lookups().await;
        }
    }

    /// Give the validators that did not answer identify yet another go: probe
    /// their advertised addresses again and, once those are exhausted, look
    /// them up again. Runs every [`RETRY_INTERVAL`] until the timeout.
    async fn retry_unidentified(&mut self) {
        let stale: Vec<(PeerId, Vec<Multiaddr>)> = self
            .peer_details
            .iter()
            .filter(|(peer, _)| {
                !self.peer_info.contains_key(*peer)
                    && !self.is_connected(peer)
                    && !self.has_pending_probes(peer)
            })
            .map(|(peer, addresses)| {
                let addresses = addresses
                    .iter()
                    .filter(|address| is_probe_candidate(address))
                    .cloned()
                    .collect();
                (*peer, addresses)
            })
            .collect();

        if stale.is_empty() {
            return;
        }
        log::debug!("Retrying {} unidentified validators", stale.len());

        for (peer, addresses) in stale {
            if !addresses.is_empty() {
                self.queued_dials.entry(peer).or_default().extend(addresses);
            }
            self.advance_peer_dial(peer).await;
            self.on_probes_exhausted(peer).await;
        }
    }

    /// Whether the discovery has nothing left to gain and can exit before the
    /// timeout: every record was found, every validator answered identify, no
    /// probe or lookup is in flight and the crawl has been quiet for a moment.
    /// Anything short of that is retried until the timeout.
    fn discovery_finished(&self) -> bool {
        if !self.remaining_authorities.is_empty() {
            return false;
        }
        if self
            .peer_details
            .keys()
            .any(|peer| !self.peer_info.contains_key(peer))
        {
            return false;
        }

        if !self.active_dials.is_empty() || !self.warm_dials.is_empty() {
            return false;
        }
        if !self.queries_discovery.is_empty() || !self.pending_lookups.is_empty() {
            return false;
        }

        // Addresses queued behind a live connection are probed once it goes
        // idle and closes, so give them that long. A connection Kademlia keeps
        // busy never closes; after two quiet keep-alive periods those
        // addresses are finalized as skipped instead.
        let queued: Vec<&PeerId> = self
            .queued_dials
            .iter()
            .filter(|(_, queue)| !queue.is_empty())
            .map(|(peer, _)| peer)
            .collect();
        if queued.iter().any(|peer| !self.is_connected(peer)) {
            return false;
        }
        if !queued.is_empty() && self.last_progress.elapsed() < self.tuning.keep_alive_timeout * 2 {
            return false;
        }

        self.last_progress.elapsed() >= Duration::from_secs(COMPLETE_QUIET_SECS)
    }

    /// Record the outcome of dialing `addr`, keeping the strongest evidence
    /// gathered for it: a success is never downgraded and a skip is only
    /// recorded when nothing else is known.
    fn record_dial_outcome(&mut self, addr: Multiaddr, outcome: DialOutcome) {
        match self.dial_outcomes.get(&addr) {
            Some(DialOutcome::Success) => (),
            Some(_) if matches!(outcome, DialOutcome::Skipped(_)) => (),
            _ => {
                self.dial_outcomes.insert(addr, outcome);
            }
        }
    }

    /// Record `outcome` for every address.
    fn record_dial_outcomes(&mut self, addresses: Vec<Multiaddr>, outcome: DialOutcome) {
        for addr in addresses {
            self.record_dial_outcome(addr, outcome.clone());
        }
    }

    /// Queue the addresses advertised by `peer_id` for dialing and start
    /// probing them.
    ///
    /// Addresses that cannot be reached from here are not dialed at all, so
    /// that they do not pollute the reachability numbers.
    async fn queue_dials(&mut self, peer_id: PeerId, addresses: &[Multiaddr]) {
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

        self.advance_peer_dial(peer_id).await;
        // Nothing dialable in the record: only a lookup can reach this peer.
        self.on_probes_exhausted(peer_id).await;
    }

    /// Put `addresses` back at the head of the queue of `peer`, to be probed
    /// once its connection is gone.
    fn requeue(&mut self, peer: PeerId, addresses: Vec<Multiaddr>) {
        let queue = self.queued_dials.entry(peer).or_default();
        for address in addresses.into_iter().rev() {
            queue.push_front(address);
        }
    }

    /// Hand `addresses` of `peer` to litep2p.
    ///
    /// While the peer did not answer identify yet, the aggressive crawl races
    /// all of them with `dial(peer)`: the first connection brings the identify
    /// response. Otherwise the addresses are probed one at a time with
    /// `dial_address`; the next one starts when the current probe resolves,
    /// since litep2p runs a single dial per peer and silently drops any other.
    /// An identified peer is never raced again: `dial(peer)` would race every
    /// address litep2p knows for it and the same one would keep winning.
    async fn start_probe(&mut self, peer: PeerId, addresses: Vec<Multiaddr>) {
        let race = self.tuning.parallel_probes && !self.peer_info.contains_key(&peer);

        if race {
            let Some(lite) = to_litep2p_peer(&peer) else {
                self.record_dial_outcomes(
                    addresses,
                    DialOutcome::Skipped("invalid peer ID".into()),
                );
                return;
            };
            self.litep2p
                .add_known_address(lite, addresses.iter().cloned());

            match self.litep2p.dial(&lite).await {
                Ok(()) => {
                    self.active_dials.insert(
                        peer,
                        ActiveDial {
                            addresses,
                            race: true,
                            started: Instant::now(),
                            attempts: 1,
                        },
                    );
                }
                // Probed once the connection is gone.
                Err(litep2p::Error::AlreadyConnected) => self.requeue(peer, addresses),
                Err(error) => {
                    self.record_dial_outcomes(addresses, DialOutcome::Failed(error.to_string()))
                }
            }
            return;
        }

        let mut rest: VecDeque<Multiaddr> = addresses.into();
        while let Some(addr) = rest.pop_front() {
            match self.litep2p.dial_address(addr.clone()).await {
                Ok(()) => {
                    self.active_dials.insert(
                        peer,
                        ActiveDial {
                            addresses: vec![addr],
                            race: false,
                            started: Instant::now(),
                            attempts: 1,
                        },
                    );
                    break;
                }
                // Probed once the connection is gone.
                Err(litep2p::Error::AlreadyConnected) => {
                    rest.push_front(addr);
                    break;
                }
                Err(error) => {
                    self.record_dial_outcome(addr, DialOutcome::Failed(error.to_string()))
                }
            }
        }
        if !rest.is_empty() {
            self.requeue(peer, rest.into());
        }
    }

    /// Probe the queued addresses of `peer_id`.
    ///
    /// While the peer is connected its remaining addresses stay queued and are
    /// retried once the connection is gone.
    async fn advance_peer_dial(&mut self, peer_id: PeerId) {
        if self.is_connected(&peer_id) || self.active_dials.contains_key(&peer_id) {
            return;
        }

        let Some(queue) = self.queued_dials.remove(&peer_id) else {
            return;
        };
        if queue.is_empty() {
            return;
        }

        self.start_probe(peer_id, queue.into()).await;
    }

    /// Dial the cached validators, up to [`MAX_WARM_DIALS`] at a time.
    ///
    /// Their records are not known yet, so this is about getting the identify
    /// response early; the addresses probed here are not probed again when the
    /// record arrives, their outcome is reused.
    async fn advance_warm_dials(&mut self) {
        while self.active_dials.len() < MAX_WARM_DIALS {
            let Some((peer, addresses)) = self.warm_dials.pop_front() else {
                break;
            };
            if self.is_connected(&peer)
                || self.active_dials.contains_key(&peer)
                || self.peer_info.contains_key(&peer)
            {
                continue;
            }

            let addresses: Vec<Multiaddr> = addresses
                .into_iter()
                .filter(is_probe_candidate)
                .filter(|address| self.dialed_addresses.insert(address.clone()))
                .collect();
            if addresses.is_empty() {
                continue;
            }

            self.warm_dialed += 1;
            self.start_probe(peer, addresses).await;
        }
    }

    /// Finish the probe of `peer` and move on to whatever is queued for it.
    ///
    /// The addresses still unresolved get `outcome`, or go back to the queue
    /// when there is none: they were not tried and will be probed one at a
    /// time later.
    async fn resolve_active_dial(&mut self, peer: PeerId, outcome: Option<DialOutcome>) {
        let Some(dial) = self.active_dials.remove(&peer) else {
            return;
        };
        match outcome {
            Some(outcome) => self.record_dial_outcomes(dial.addresses, outcome),
            None => self.requeue(peer, dial.addresses),
        }
        self.touch_progress();

        self.advance_peer_dial(peer).await;
        self.on_probes_exhausted(peer).await;
        self.advance_warm_dials().await;
    }

    /// Issue the running probe of `peer` again.
    ///
    /// Called when the probe never reached the network: litep2p dropped it
    /// because Kademlia was dialing the peer at the time. The peer is
    /// disconnected now, so the dial slot is free. After a few attempts the
    /// addresses are given up on rather than mistaken for unreachable.
    async fn restart_active_dial(&mut self, peer: PeerId) {
        let Some(dial) = self.active_dials.get_mut(&peer) else {
            return;
        };

        if dial.attempts >= MAX_DIAL_ATTEMPTS {
            log::debug!(
                "Giving up on probing {:?} after {} attempts",
                dial.addresses,
                dial.attempts
            );
            self.resolve_active_dial(
                peer,
                Some(DialOutcome::Skipped("dial superseded by kademlia".into())),
            )
            .await;
            return;
        }

        dial.attempts += 1;
        dial.started = Instant::now();
        let race = dial.race;
        let first = dial.addresses.first().cloned();

        let result = if race {
            match to_litep2p_peer(&peer) {
                Some(lite) => self.litep2p.dial(&lite).await,
                None => return,
            }
        } else {
            match first {
                Some(address) => self.litep2p.dial_address(address).await,
                None => return,
            }
        };

        match result {
            Ok(()) => (),
            Err(litep2p::Error::AlreadyConnected) => self.resolve_active_dial(peer, None).await,
            Err(error) => {
                self.resolve_active_dial(peer, Some(DialOutcome::Failed(error.to_string())))
                    .await
            }
        }
    }

    /// Retry the addresses that stayed queued because their peer was connected
    /// or already had a probe in flight.
    async fn drain_queued_dials(&mut self) {
        let peers: Vec<PeerId> = self.queued_dials.keys().copied().collect();
        for peer in peers {
            self.advance_peer_dial(peer).await;
        }
    }

    /// Deal with the probes that did not resolve in time, see
    /// [`Tuning::dial_stall_timeout`].
    async fn check_stalled_dials(&mut self) {
        let stall = self.tuning.dial_stall_timeout();
        let stalled: Vec<PeerId> = self
            .active_dials
            .iter()
            .filter(|(_, dial)| dial.started.elapsed() >= stall)
            .map(|(peer, _)| *peer)
            .collect();

        for peer in stalled {
            if self.is_connected(&peer) {
                self.resolve_active_dial(peer, None).await;
            } else {
                self.restart_active_dial(peer).await;
            }
        }
    }

    /// Account for the addresses that were never probed once the discovery is
    /// over, so that they are not mistaken for unreachable ones.
    fn finalize_queued_dials(&mut self) {
        let queued: Vec<(PeerId, VecDeque<Multiaddr>)> = self.queued_dials.drain().collect();
        for (peer, addresses) in queued {
            let reason = if self.is_connected(&peer) {
                "peer already connected"
            } else {
                "discovery ended before probing"
            };

            for addr in addresses {
                self.record_dial_outcome(addr, DialOutcome::Skipped(reason.into()));
            }
        }
    }

    /// Dials failed. `complete` says whether the whole dial of each peer
    /// failed (every address litep2p tried is listed), as opposed to a single
    /// address out of several still racing.
    ///
    /// Only our own probes say something about a specific address; Kademlia
    /// dials the same peers over and over during the crawl and its failures
    /// must not overwrite what we learned. They do tell us one thing though:
    /// a Kademlia dial failing while our probe of the same peer is out means
    /// litep2p dropped the probe, so it is issued again.
    async fn on_dial_failures(&mut self, failures: Vec<(Multiaddr, String)>, complete: bool) {
        let mut by_peer: HashMap<PeerId, Vec<(Multiaddr, String)>> = HashMap::new();
        for (address, error) in failures {
            // Every address dialed by litep2p carries the peer ID.
            if let Some(peer) = get_peer_id(&address) {
                by_peer.entry(peer).or_default().push((address, error));
            }
        }

        for (peer, failures) in by_peer {
            let Some(dial) = self.active_dials.get_mut(&peer) else {
                continue;
            };

            let mut failed = Vec::new();
            for (address, error) in failures {
                let probed = without_peer_id(&address);
                if let Some(pos) = dial
                    .addresses
                    .iter()
                    .position(|candidate| without_peer_id(candidate) == probed)
                {
                    failed.push((dial.addresses.remove(pos), error));
                }
            }
            let exhausted = complete || dial.addresses.is_empty();

            if failed.is_empty() {
                self.restart_active_dial(peer).await;
                continue;
            }

            for (address, error) in failed {
                self.record_dial_outcome(address, DialOutcome::Failed(error));
            }
            if exhausted {
                // Addresses of ours that litep2p did not try are not evidence
                // either way; they are probed one at a time next.
                self.resolve_active_dial(peer, None).await;
            }
        }
    }

    /// Handle a connection level event.
    async fn handle_network_event(&mut self, event: Litep2pEvent) {
        match event {
            Litep2pEvent::ConnectionEstablished { peer, endpoint } => {
                let Some(peer_id) = from_litep2p_peer(&peer) else {
                    return;
                };
                self.reached_peers.insert(peer_id);
                self.connections
                    .entry(peer_id)
                    .or_default()
                    .insert(endpoint.connection_id());

                // The address that carried the connection is reachable, no
                // matter who started the dial: Kademlia opens connections of
                // its own during the crawl and they prove the same thing. The
                // outcome is recorded in the DHT record form, with the peer.
                let address = match &endpoint {
                    Endpoint::Dialer { address, .. } => Some(with_peer_id(address, peer_id)),
                    Endpoint::Listener { .. } => None,
                };
                if let Some(address) = &address {
                    self.record_dial_outcome(address.clone(), DialOutcome::Success);
                }

                // The other addresses of the probe lost the race, or litep2p
                // dropped the probe because the connection came through
                // Kademlia's dial. Either way nothing is known about them yet;
                // substrate nodes keep a single connection per peer, so they
                // wait in the queue until this connection is gone.
                if let Some(dial) = self.active_dials.remove(&peer_id) {
                    let (won, lost): (Vec<Multiaddr>, Vec<Multiaddr>) = dial
                        .addresses
                        .into_iter()
                        .partition(|probed| Some(probed) == address.as_ref());
                    self.record_dial_outcomes(won, DialOutcome::Success);
                    self.requeue(peer_id, lost);
                    self.touch_progress();
                    self.advance_warm_dials().await;
                }

                // A fresh connection to a not-yet-identified validator will
                // produce an identify response shortly; hold the early exit
                // until it lands.
                if self.is_unidentified_validator(&peer_id) {
                    self.touch_progress();
                }

                log::trace!(
                    "Connection established: peer_id={:?} endpoint={:?}",
                    peer_id,
                    endpoint,
                );
            }

            Litep2pEvent::ConnectionClosed {
                peer,
                connection_id,
            } => {
                let Some(peer_id) = from_litep2p_peer(&peer) else {
                    return;
                };
                log::trace!(
                    "Connection closed: peer_id={:?} connection_id={:?}",
                    peer_id,
                    connection_id,
                );

                let disconnected = match self.connections.get_mut(&peer_id) {
                    Some(connections) => {
                        connections.remove(&connection_id);
                        connections.is_empty()
                    }
                    None => true,
                };

                // The addresses still queued for this peer could not be probed
                // while it was connected; probe them now. For a validator that
                // dropped the connection before answering identify this is
                // also the next chance to reach it.
                if disconnected {
                    self.connections.remove(&peer_id);
                    self.advance_peer_dial(peer_id).await;
                    self.on_probes_exhausted(peer_id).await;
                }
            }

            Litep2pEvent::DialFailure { address, error } => {
                log::trace!("Dial failure: address={:?} error={:?}", address, error);
                // A single address failing is the whole dial in the standard
                // crawl, and one of several racing addresses in the
                // aggressive one.
                let complete = !self.tuning.parallel_probes;
                self.on_dial_failures(vec![(address, error.to_string())], complete)
                    .await;
            }

            Litep2pEvent::ListDialFailures { errors } => {
                log::trace!("Dial failures: {:?}", errors);
                let failures = errors
                    .into_iter()
                    .map(|(address, error)| (address, error.to_string()))
                    .collect();
                self.on_dial_failures(failures, true).await;
            }
        }
    }

    /// A DHT record was found for one of the queries.
    async fn on_record(&mut self, record: PeerRecord) {
        let PeerRecord { record, .. } = record;
        let key = record.key.to_vec();

        let Some(authority) = self.records_keys.get(&key).copied() else {
            return;
        };

        let (peer_id, addresses) = match decode_dht_record(record.value, &authority) {
            Ok((peer_id, addresses)) => (peer_id, addresses),
            Err(e) => {
                log::debug!(
                    " Decoding DHT failed for authority {:?}: {:?}",
                    authority,
                    e
                );
                self.dht_errors += 1;
                return;
            }
        };

        self.authority_to_details
            .entry(authority)
            .or_default()
            .extend(addresses.iter().cloned());
        self.peer_details
            .entry(peer_id)
            .or_default()
            .extend(addresses.iter().cloned());

        // Make the addresses known to the transport and to the routing table,
        // so that a lookup for the validator dials it with them.
        if let Some(peer) = to_litep2p_peer(&peer_id) {
            self.litep2p
                .add_known_address(peer, addresses.iter().cloned());
            self.kademlia.add_known_peer(peer, addresses.clone()).await;
        }

        // Probe the advertised addresses through the litep2p stack (noise
        // handshake, yamux) to test reachability per address.
        self.queue_dials(peer_id, &addresses).await;

        log::debug!(
            "{}/{} (err {}) authority: {:?} peer_id {:?} Addresses: {:?}",
            self.authority_to_details.len(),
            self.authorities.len(),
            self.dht_errors,
            authority,
            peer_id,
            addresses
        );

        let now = Instant::now();
        if now.duration_since(self.old_log) > Duration::from_secs(10) {
            self.old_log = now;
            log::info!(
                "... DHT records {}/{} (err {}) | Identified {}/{} | Active peer queries {} | authority={:?} peer_id={:?} addresses={:?}",
                self.authority_to_details.len(),
                self.authorities.len(),
                self.dht_errors,
                self.peer_details.keys().filter(|peer| self.peer_info.contains_key(peer)).count(),
                self.peer_details.len(),
                self.queries_discovery.len(),
                authority,
                peer_id,
                addresses
            );
        }

        if self.remaining_authorities.remove(&authority) {
            self.touch_progress();
        }
    }

    /// Handle a Kademlia event.
    async fn handle_kademlia_event(&mut self, event: KademliaEvent) {
        log::trace!("Kademlia event: {:?}", event);

        match event {
            KademliaEvent::GetRecordPartialResult { record, .. } => {
                self.on_record(record).await;
            }

            // With `Quorum::One` the query completes right after the first
            // record; a query that found nothing fails once it runs out of
            // peers to ask. Either way the slot is free again.
            KademliaEvent::GetRecordSuccess { query_id }
            | KademliaEvent::QueryFailed { query_id } => {
                if self.queries.remove(&query_id).is_some() {
                    log::debug!(
                        "DHT query {:?} finished (in-flight: {}, remaining: {})",
                        query_id,
                        self.queries.len(),
                        self.remaining_authorities.len()
                    );
                    self.advance_dht_queries().await;
                } else if let Some((peer, _)) = self.queries_discovery.remove(&query_id) {
                    log::debug!(
                        "Lookup for validator {:?} failed, identified: {}",
                        peer,
                        self.peer_info.contains_key(&peer),
                    );
                    self.advance_peer_lookups().await;
                }
            }

            KademliaEvent::FindNodeSuccess {
                query_id, peers, ..
            } => {
                let Some((peer, _)) = self.queries_discovery.remove(&query_id) else {
                    return;
                };
                log::debug!(
                    "Lookup for validator {:?} finished: {} peers, identified: {}",
                    peer,
                    peers.len(),
                    self.peer_info.contains_key(&peer),
                );
                self.advance_peer_lookups().await;
            }

            // The routing table filling up is what lets the aggressive crawl
            // release the rest of its queries.
            KademliaEvent::RoutingTableUpdate { peers } => {
                let before = self.routing_peers.len();
                self.routing_peers
                    .extend(peers.iter().filter_map(from_litep2p_peer));
                if self.tuning.ramp_routing_peers > 0
                    && before < self.tuning.ramp_routing_peers
                    && self.routing_peers.len() >= self.tuning.ramp_routing_peers
                {
                    log::info!(
                        "Routing table holds {} peers, releasing all record queries",
                        self.routing_peers.len()
                    );
                    self.advance_dht_queries().await;
                }
            }

            _ => (),
        }
    }

    /// Handle an identify response.
    fn handle_identify_event(&mut self, event: IdentifyEvent) {
        let IdentifyEvent::PeerIdentified {
            peer,
            user_agent,
            listen_addresses,
            ..
        } = event;

        let Some(peer_id) = from_litep2p_peer(&peer) else {
            return;
        };

        // A validator identify response is the goal of the whole crawl, so it
        // counts as progress. Identifies of random network peers do not: they
        // arrive for as long as Kademlia crawls.
        if self.is_unidentified_validator(&peer_id) {
            self.touch_progress();
        }

        self.peer_info.insert(
            peer_id,
            IdentifyInfo {
                agent_version: user_agent.unwrap_or_default(),
                listen_addrs: listen_addresses,
            },
        );
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

        let connected_peers = self.connections.len();
        let queries_inflight = self.queries.len();
        let lookups_inflight = self.queries_discovery.len() + self.pending_lookups.len();
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
        let warm = if self.warm_dialed > 0 || !self.warm_dials.is_empty() {
            format!(
                " | Warm: {}/{}",
                self.warm_dialed,
                self.warm_dialed + self.warm_dials.len()
            )
        } else {
            String::new()
        };

        print!(
            "\r       [{}] {}/{} ({:.1}%) | Id: {} | Dials: {}/{} ok | Err: {} | Peers: {} | Q: {} | L: {}{} | {}s/{}s   ",
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
            lookups_inflight,
            warm,
            elapsed,
            self.timeout_secs,
        );
        let _ = std::io::stdout().flush();
    }

    /// Clear the progress line.
    fn clear_progress(&self) {
        if self.show_progress {
            print!("\r{}\r", " ".repeat(120));
            let _ = std::io::stdout().flush();
        }
    }

    /// Run the discovery process.
    pub async fn discover(&mut self) {
        self.advance_dht_queries().await;
        self.advance_warm_dials().await;
        self.start_time = Instant::now();
        self.last_progress = Instant::now();

        // Should return immediately.
        self.interval_resubmit.tick().await;
        self.interval_exit.tick().await;
        self.interval_retry.tick().await;

        let mut progress_interval = tokio::time::interval(Duration::from_secs(1));
        progress_interval.tick().await;

        loop {
            // The event is handled outside of the select so that the handlers
            // are free to use the whole state.
            let event = tokio::select! {
                event = self.litep2p.next_event() => Event::Network(event),
                event = self.kademlia.next() => Event::Kademlia(event),
                event = self.identify.next() => Event::Identify(event),
                event = self.ping.next() => Event::Ping(event),
                _ = self.interval_resubmit.tick() => Event::Resubmit,
                _ = self.interval_retry.tick() => Event::Retry,
                _ = progress_interval.tick() => Event::Progress,
                _ = self.interval_exit.tick() => Event::Exit,
            };

            match event {
                Event::Network(Some(event)) => self.handle_network_event(event).await,
                Event::Kademlia(Some(event)) => self.handle_kademlia_event(event).await,
                Event::Identify(Some(event)) => self.handle_identify_event(event),
                Event::Ping(Some(_)) => (),

                Event::Network(None)
                | Event::Kademlia(None)
                | Event::Identify(None)
                | Event::Ping(None) => {
                    self.clear_progress();
                    log::warn!("litep2p stopped producing events, exiting discovery");
                    return;
                }

                Event::Resubmit => {
                    self.expire_stale_queries();
                    self.advance_dht_queries().await;
                    self.drain_queued_dials().await;
                    self.advance_warm_dials().await;
                }

                Event::Retry => {
                    self.retry_unidentified().await;
                }

                Event::Progress => {
                    if self.show_progress {
                        self.print_progress();
                    }

                    // Slots held by slow queries are reused right away, like
                    // the libp2p query timeout does.
                    self.expire_stale_queries();
                    self.advance_dht_queries().await;
                    self.check_stalled_dials().await;
                    self.advance_warm_dials().await;

                    if self.discovery_finished() {
                        self.clear_progress();
                        log::info!(
                            "All authorities discovered and identified, exiting early after {}s",
                            self.start_time.elapsed().as_secs()
                        );
                        return;
                    }
                }

                Event::Exit => {
                    self.clear_progress();

                    let unidentified = self
                        .peer_details
                        .keys()
                        .filter(|peer| !self.peer_info.contains_key(peer))
                        .count();
                    log::info!(
                        "Timeout reached: {} records missing, {} validators never identified",
                        self.remaining_authorities.len(),
                        unidentified
                    );

                    return;
                }
            }
        }
    }

    /// Consume the discovery state and return the collected results, in the
    /// same shape as the libp2p implementation.
    ///
    /// This drops the litep2p stack, freeing its network connections and file
    /// descriptors so that the TCP reachability checks that follow do not hit
    /// the open-file limit.
    pub fn into_results(mut self) -> DiscoveryResults {
        self.finalize_queued_dials();

        (
            self.authority_to_details,
            self.peer_info,
            self.dial_outcomes,
            self.reached_peers,
        )
    }
}
