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
//! - litep2p keeps a single dial in flight per peer. Dialing another address
//!   of a peer that is already being dialed is accepted and silently dropped,
//!   so the probes of a peer run one after the other rather than concurrently.
//! - Dial results are reported per address, not per connection id, and the
//!   failures of Kademlia's own dials arrive through the same events. The
//!   address of an established connection is rebuilt from the socket, so it
//!   lacks the `/p2p/<peer>` suffix carried by the DHT record addresses.
//! - Queries cannot be cancelled, so the query timeout is enforced here by
//!   forgetting about a query once it ran for too long.

use crate::commands::authorities::{
    DialOutcome, COMPLETE_QUIET_SECS, MAX_LOOKUPS, MAX_QUERIES, STALL_QUIET_SECS,
};
use crate::commands::authority_check::{DiscoveryResults, IdentifyInfo};
use crate::utils::{is_dialable_transport, is_public_address};
use futures::{Stream, StreamExt};
use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
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

/// Dial timeout of the litep2p transports. Every dial that reaches the
/// network resolves within this time, with a connection or with a failure.
const CONNECTION_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// A probe that did not resolve within this time never reached the network:
/// litep2p dropped it because Kademlia was already dialing the same peer.
const DIAL_STALL_TIMEOUT: Duration = Duration::from_secs(20);

/// Number of times a dropped probe is issued again before giving up on it.
const MAX_DIAL_ATTEMPTS: u8 = 3;

type IdentifyStream = Box<dyn Stream<Item = IdentifyEvent> + Send + Unpin>;
type PingStream = Box<dyn Stream<Item = PingEvent> + Send + Unpin>;

/// A probe of one advertised address of a peer.
#[derive(Debug)]
struct ActiveDial {
    /// Address being probed.
    address: Multiaddr,
    /// When the current attempt was issued.
    started: Instant,
    /// Number of times the probe was issued, see [`DIAL_STALL_TIMEOUT`].
    attempts: u8,
}

/// Something the crawl has to react to.
enum Event {
    Network(Option<Litep2pEvent>),
    Kademlia(Option<KademliaEvent>),
    Identify(Option<IdentifyEvent>),
    Ping(Option<PingEvent>),
    Resubmit,
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

    /// In flight `get-record` queries, with the time they were submitted, to
    /// keep at most `MAX_QUERIES` running and expire the slow ones.
    queries: HashMap<QueryId, (sr25519::PublicKey, Instant)>,
    /// In flight `find-node` lookups for validators that were not reached at
    /// their advertised addresses.
    queries_discovery: HashMap<QueryId, (PeerId, Instant)>,

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

    /// Whether to print an interactive progress bar to stdout.
    show_progress: bool,
    /// When the discovery process started.
    start_time: Instant,
    /// Timeout duration for display purposes.
    timeout_secs: u64,

    /// Per-address dial outcomes (noise + yamux upgrade).
    dial_outcomes: HashMap<Multiaddr, DialOutcome>,
    /// Addresses already queued for dialing. Deduplicates addresses advertised
    /// by more than one authority record.
    dialed_addresses: HashSet<Multiaddr>,
    /// Addresses waiting to be dialed, per peer.
    queued_dials: HashMap<PeerId, VecDeque<Multiaddr>>,
    /// The probe currently running for each peer. litep2p runs a single dial
    /// per peer, so there is at most one.
    active_dials: HashMap<PeerId, ActiveDial>,
    /// Open connections per peer.
    connections: HashMap<PeerId, HashSet<ConnectionId>>,

    /// Every distinct peer a connection was established with during the crawl,
    /// validators and regular network nodes alike.
    reached_peers: HashSet<PeerId>,

    /// Validators whose advertised addresses were all probed without an
    /// identify response, waiting for a lookup slot.
    pending_lookups: VecDeque<PeerId>,
    /// Validators a targeted lookup was already started for.
    looked_up: HashSet<PeerId>,
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

/// The address without its trailing `/p2p/<peer>` component, for comparing
/// what was dialed with what litep2p reports.
fn without_peer_id(address: &Multiaddr) -> Multiaddr {
    let mut address = address.clone();
    if matches!(address.iter().last(), Some(Protocol::P2p(_))) {
        address.pop();
    }
    address
}

/// The address with exactly one trailing `/p2p/<peer>` component, the form
/// used by the DHT records and by every address probed here.
fn with_peer_id(address: &Multiaddr, peer: PeerId) -> Multiaddr {
    without_peer_id(address).with(Protocol::P2p(peer))
}

/// Split a bootnode string into the peer and the address.
fn parse_bootnode(bootnode: &str) -> Option<(Litep2pPeerId, Multiaddr)> {
    let address: Multiaddr = bootnode.parse().ok()?;
    let peer = Litep2pPeerId::try_from_multiaddr(&address)?;
    Some((peer, address))
}

impl Litep2pAuthorityDiscovery {
    /// Constructs a new [`Litep2pAuthorityDiscovery`].
    ///
    /// Builds the litep2p stack with the same protocols as the libp2p swarm:
    /// TCP and WebSocket transports, ping, identify and the chain-specific
    /// Kademlia protocol seeded with the bootnodes. No notification protocol
    /// is registered, so connections close as soon as they go idle instead of
    /// holding a slot on both sides until the crawl ends.
    pub fn new(
        genesis: &str,
        bootnodes: Vec<String>,
        authorities: Vec<sr25519::PublicKey>,
        timeout: Duration,
        query_timeout: Duration,
    ) -> Result<Self, Box<dyn Error>> {
        let genesis = genesis.trim_start_matches("0x");

        let known_peers: HashMap<Litep2pPeerId, Vec<Multiaddr>> =
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
                connection_open_timeout: CONNECTION_OPEN_TIMEOUT,
                ..Default::default()
            })
            .with_websocket(WebSocketConfig {
                listen_addresses: Vec::new(),
                nodelay: true,
                connection_open_timeout: CONNECTION_OPEN_TIMEOUT,
                ..Default::default()
            })
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

            queries: HashMap::with_capacity(1024),
            queries_discovery: HashMap::with_capacity(MAX_LOOKUPS),

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

            show_progress: false,
            start_time: Instant::now(),
            timeout_secs: timeout.as_secs(),

            dial_outcomes: HashMap::with_capacity(4096),
            dialed_addresses: HashSet::with_capacity(4096),
            queued_dials: HashMap::with_capacity(1024),
            active_dials: HashMap::with_capacity(1024),
            connections: HashMap::with_capacity(1024),

            reached_peers: HashSet::with_capacity(4096),

            pending_lookups: VecDeque::new(),
            looked_up: HashSet::with_capacity(256),
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

    /// Submit at most `MAX_QUERIES` DHT queries to find authority records.
    ///
    /// After one query is submitted for every authority this method backfills
    /// the free slots with the authorities whose record was not found yet.
    async fn advance_dht_queries(&mut self) {
        while self.queries.len() < MAX_QUERIES {
            if let Some(next) = self.authorities.get(self.query_index) {
                self.query_dht_records(std::iter::once(*next)).await;
                self.query_index += 1;
            } else {
                break;
            }
        }

        if self.query_index >= self.authorities.len() && self.queries.len() < MAX_QUERIES {
            let in_flight: HashSet<_> = self
                .queries
                .values()
                .map(|(authority, _)| *authority)
                .collect();
            let backfill: Vec<_> = self
                .remaining_authorities
                .iter()
                .filter(|a| !in_flight.contains(*a))
                .take(MAX_QUERIES - self.queries.len())
                .copied()
                .collect();

            if !backfill.is_empty() {
                self.query_dht_records(backfill).await;
            }
        }

        log::debug!(
            "queries: {} remaining authorities to discover {}",
            self.queries.len(),
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
    /// implementation for the full reasoning.
    async fn on_probes_exhausted(&mut self, peer: PeerId) {
        if self.is_connected(&peer)
            || !self.is_unidentified_validator(&peer)
            || self.has_pending_probes(&peer)
        {
            return;
        }

        if self.looked_up.insert(peer) {
            self.pending_lookups.push_back(peer);
            self.advance_peer_lookups().await;
        }
    }

    /// Whether the discovery has nothing left to do and can exit before the
    /// timeout. Same rules as the libp2p implementation.
    fn discovery_finished(&self) -> bool {
        if !self.active_dials.is_empty() {
            return false;
        }

        if !self.queries_discovery.is_empty() || !self.pending_lookups.is_empty() {
            return false;
        }

        if !self.queued_dials.keys().all(|peer| self.is_connected(peer)) {
            return false;
        }

        let quiet_secs = if self.remaining_authorities.is_empty() {
            COMPLETE_QUIET_SECS
        } else {
            STALL_QUIET_SECS
        };
        self.last_progress.elapsed() >= Duration::from_secs(quiet_secs)
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

    /// Issue a dial for `address`. Errors are the outcome to record for the
    /// address: the dial never reached the network.
    async fn dial(&mut self, address: &Multiaddr) -> Result<(), DialOutcome> {
        match self.litep2p.dial_address(address.clone()).await {
            Ok(()) => Ok(()),
            Err(litep2p::Error::AlreadyConnected) => {
                Err(DialOutcome::Skipped("peer already connected".into()))
            }
            Err(error) => Err(DialOutcome::Failed(error.to_string())),
        }
    }

    /// Probe the next queued address of `peer_id`.
    ///
    /// litep2p runs a single dial per peer and silently drops any other, so the
    /// addresses are probed one at a time; the next one starts when the
    /// current probe resolves. While the peer is connected its remaining
    /// addresses stay queued and are retried once the connection is gone.
    async fn advance_peer_dial(&mut self, peer_id: PeerId) {
        if self.is_connected(&peer_id) || self.active_dials.contains_key(&peer_id) {
            return;
        }

        let Some(mut queue) = self.queued_dials.remove(&peer_id) else {
            return;
        };

        while let Some(addr) = queue.pop_front() {
            match self.dial(&addr).await {
                Ok(()) => {
                    self.active_dials.insert(
                        peer_id,
                        ActiveDial {
                            address: addr,
                            started: Instant::now(),
                            attempts: 1,
                        },
                    );
                    break;
                }
                Err(outcome) => self.record_dial_outcome(addr, outcome),
            }
        }

        if !queue.is_empty() {
            self.queued_dials.insert(peer_id, queue);
        }
    }

    /// Finish the probe of `peer` with `outcome` and move on to its next
    /// address.
    async fn resolve_active_dial(&mut self, peer: PeerId, outcome: DialOutcome) {
        let Some(dial) = self.active_dials.remove(&peer) else {
            return;
        };
        self.record_dial_outcome(dial.address, outcome);
        self.touch_progress();

        self.advance_peer_dial(peer).await;
        self.on_probes_exhausted(peer).await;
    }

    /// Issue the running probe of `peer` again.
    ///
    /// Called when the probe never reached the network: litep2p dropped it
    /// because Kademlia was dialing the peer at the time. The peer is
    /// disconnected now, so the dial slot is free. After a few attempts the
    /// address is given up on rather than mistaken for unreachable.
    async fn restart_active_dial(&mut self, peer: PeerId) {
        let Some(dial) = self.active_dials.get_mut(&peer) else {
            return;
        };

        if dial.attempts >= MAX_DIAL_ATTEMPTS {
            log::debug!(
                "Giving up on probing {} after {} attempts",
                dial.address,
                dial.attempts
            );
            self.resolve_active_dial(
                peer,
                DialOutcome::Skipped("dial superseded by kademlia".into()),
            )
            .await;
            return;
        }

        dial.attempts += 1;
        dial.started = Instant::now();
        let address = dial.address.clone();

        if let Err(outcome) = self.dial(&address).await {
            self.resolve_active_dial(peer, outcome).await;
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
    /// [`DIAL_STALL_TIMEOUT`].
    async fn check_stalled_dials(&mut self) {
        let stalled: Vec<PeerId> = self
            .active_dials
            .iter()
            .filter(|(_, dial)| dial.started.elapsed() >= DIAL_STALL_TIMEOUT)
            .map(|(peer, _)| *peer)
            .collect();

        for peer in stalled {
            if self.is_connected(&peer) {
                self.resolve_active_dial(
                    peer,
                    DialOutcome::Skipped("peer already connected".into()),
                )
                .await;
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

    /// A dial to `address` failed with `error`.
    ///
    /// Only our own probes say something about a specific address; Kademlia
    /// dials the same peers over and over during the crawl and its failures
    /// must not overwrite what we learned.
    async fn on_dial_failure(&mut self, address: Multiaddr, error: String) {
        // Every address dialed by litep2p carries the peer ID.
        let Some(peer) = get_peer_id(&address) else {
            return;
        };
        let Some(dial) = self.active_dials.get(&peer) else {
            return;
        };

        if without_peer_id(&dial.address) == without_peer_id(&address) {
            self.resolve_active_dial(peer, DialOutcome::Failed(error))
                .await;
        } else {
            // A Kademlia dial of this peer failed while our probe was issued,
            // which means litep2p dropped the probe. Issue it again now that
            // the peer is disconnected.
            self.restart_active_dial(peer).await;
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

                if let Some(dial) = self.active_dials.remove(&peer_id) {
                    if address.as_ref() == Some(&dial.address) {
                        self.record_dial_outcome(dial.address, DialOutcome::Success);
                    } else {
                        // The connection came through another address, so
                        // litep2p dropped our probe and nothing is known about
                        // the address it was meant for. Substrate nodes keep a
                        // single connection per peer anyway.
                        self.record_dial_outcome(
                            dial.address,
                            DialOutcome::Skipped("peer already connected".into()),
                        );
                    }
                    self.touch_progress();
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
                self.on_dial_failure(address, error.to_string()).await;
            }

            Litep2pEvent::ListDialFailures { errors } => {
                for (address, error) in errors {
                    log::trace!("Dial failure: address={:?} error={:?}", address, error);
                    self.on_dial_failure(address, error.to_string()).await;
                }
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

        print!(
            "\r       [{}] {}/{} ({:.1}%) | Id: {} | Dials: {}/{} ok | Err: {} | Peers: {} | Q: {} | L: {} | {}s/{}s   ",
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
            elapsed,
            self.timeout_secs,
        );
        let _ = std::io::stdout().flush();
    }

    /// Clear the progress line.
    fn clear_progress(&self) {
        if self.show_progress {
            print!("\r{}\r", " ".repeat(100));
            let _ = std::io::stdout().flush();
        }
    }

    /// Run the discovery process.
    pub async fn discover(&mut self) {
        self.advance_dht_queries().await;
        self.start_time = Instant::now();
        self.last_progress = Instant::now();

        // Should return immediately.
        self.interval_resubmit.tick().await;
        self.interval_exit.tick().await;

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

                    if self.discovery_finished() {
                        self.clear_progress();

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

                Event::Exit => {
                    self.clear_progress();

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
