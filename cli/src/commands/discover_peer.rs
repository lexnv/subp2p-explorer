// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use crate::commands::authorities::{fetch_genesis_hash, resolve_bootnodes};
use crate::utils::build_swarm;
use codec::Decode;
use futures::{FutureExt, StreamExt};
use jsonrpsee::client_transport::ws::Url;
use libp2p::{
    identify::Info,
    kad::{Event as KademliaEvent, GetClosestPeersError, GetClosestPeersOk, QueryId, QueryResult},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::error::Error;
use std::time::Duration;
use subp2p_explorer::{
    notifications::{behavior::NotificationsToSwarm, messages::ProtocolRole},
    peer_behavior::PeerInfoEvent,
    Behaviour, BehaviourEvent,
};

/// Maximum number of concurrent `get-closest-peers` queries kept in flight,
/// all keyed on the target peer ID. Each completed query is immediately
/// replaced so DHT pressure stays constant on the target neighborhood.
const MAX_QUERIES: usize = 128;

struct PeerDiscovery {
    /// The target peer ID we are hunting.
    target: PeerId,
    /// Drive the network behavior.
    swarm: Swarm<Behaviour>,
    /// In flight kademlia `get-closest-peers` queries, all keyed on `target`.
    queries: HashSet<QueryId>,
    /// Discovered peers by kademlia queries.
    discovered_with_addresses: HashMap<PeerId, HashSet<Multiaddr>>,
    /// Peer details including protocols, multiaddress.
    peer_details: HashMap<PeerId, Info>,
    /// Peers that announced their role.
    peer_role: HashMap<PeerId, ProtocolRole>,
    /// Addresses for which a libp2p dial has been initiated, used to avoid
    /// dialing the same address repeatedly.
    dialed_addresses: HashSet<Multiaddr>,
    /// Set once we have received an identify response from the target.
    target_identified: bool,
    /// Number of distinct DHT events that surfaced an address for the target,
    /// regardless of whether we successfully connected. Counts every
    /// `RoutingUpdated` / `RoutablePeer` / `PendingRoutablePeer` /
    /// closest-peers response that named the target.
    target_dht_reports: usize,
    /// Addresses learned for the target via the DHT (deduped). Updated even
    /// when dials fail, so we can show progress when other peers know the
    /// target but it is unreachable from us.
    target_known_addresses: HashSet<Multiaddr>,
}

impl PeerDiscovery {
    pub fn new(target: PeerId, swarm: Swarm<Behaviour>) -> Self {
        Self {
            target,
            swarm,
            queries: HashSet::with_capacity(MAX_QUERIES),
            discovered_with_addresses: HashMap::with_capacity(1024),
            peer_details: HashMap::with_capacity(1024),
            peer_role: HashMap::with_capacity(1024),
            dialed_addresses: HashSet::with_capacity(4096),
            target_identified: false,
            target_dht_reports: 0,
            target_known_addresses: HashSet::new(),
        }
    }

    /// Record that the DHT surfaced address(es) for the target peer through
    /// some other peer's routing table response. Logs progress for every
    /// genuinely new address; bumps the counter unconditionally so the user
    /// can see DHT activity even if all addresses are already known.
    fn note_target_addresses<I>(&mut self, source: &str, addrs: I)
    where
        I: IntoIterator<Item = Multiaddr>,
    {
        self.target_dht_reports += 1;
        let mut new_addrs = Vec::new();
        for addr in addrs {
            if self.target_known_addresses.insert(addr.clone()) {
                new_addrs.push(addr);
            }
        }
        if new_addrs.is_empty() {
            log::debug!(
                "DHT progress: {source} re-reported known addresses for target {} (reports={})",
                self.target,
                self.target_dht_reports
            );
        } else {
            println!(
                "DHT progress: {source} reported {} new address(es) for target {} (total known={}, reports={})",
                new_addrs.len(),
                self.target,
                self.target_known_addresses.len(),
                self.target_dht_reports,
            );
            for addr in new_addrs {
                println!("  + {addr}");
            }
        }
    }

    /// Top up the in-flight `get-closest-peers` queries so that exactly
    /// [`MAX_QUERIES`] queries are always running, each keyed on the target.
    fn top_up_queries(&mut self) {
        while self.queries.len() < MAX_QUERIES {
            self.queries.insert(
                self.swarm
                    .behaviour_mut()
                    .discovery
                    .get_closest_peers(self.target),
            );
        }
    }

    /// Force-dial a freshly-discovered address through the full libp2p
    /// stack to trigger noise + yamux + identify + notification handshakes.
    fn force_dial(&mut self, peer: PeerId, addr: Multiaddr) {
        if !self.dialed_addresses.insert(addr.clone()) {
            return;
        }
        self.swarm
            .behaviour_mut()
            .discovery
            .add_address(&peer, addr.clone());
        if let Err(e) = self.swarm.dial(addr.clone()) {
            log::trace!("Dial failed peer={peer} addr={addr}: {e:?}");
        }
    }

    pub async fn drive_events(&mut self) {
        // Prime the DHT with a full batch of target-keyed queries.
        self.top_up_queries();

        let mut resubmit_interval = tokio::time::interval(Duration::from_secs(15));
        resubmit_interval.tick().await;

        let mut log_interval = tokio::time::interval(Duration::from_secs(10));
        log_interval.tick().await;

        loop {
            futures::select! {
                event = self.swarm.select_next_some().fuse() => {
                    self.handle_event(event);
                }

                _ = resubmit_interval.tick().fuse() => {
                    self.top_up_queries();
                }

                _ = log_interval.tick().fuse() => {
                    log::info!(
                        "...Peer discovery target={} identified_target={} target_dht_reports={} target_known_addrs={} discovered={} identified={} dialed_addrs={} queries_in_flight={}",
                        self.target,
                        self.target_identified,
                        self.target_dht_reports,
                        self.target_known_addresses.len(),
                        self.discovered_with_addresses.len(),
                        self.peer_details.len(),
                        self.dialed_addresses.len(),
                        self.queries.len(),
                    );
                }
            }
        }
    }

    fn handle_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::Discovery(event)) => match event {
                KademliaEvent::OutboundQueryProgressed {
                    id,
                    result: QueryResult::GetClosestPeers(result),
                    ..
                } => {
                    self.queries.remove(&id);

                    let peers = match result {
                        Ok(GetClosestPeersOk { peers, .. }) => peers,
                        Err(GetClosestPeersError::Timeout { peers, .. }) => peers,
                    };

                    // Surface addresses other peers reported for the target
                    // inside the closest-peers response itself, even before
                    // they bubble up as RoutablePeer / RoutingUpdated.
                    let target_addrs: Vec<Multiaddr> = peers
                        .iter()
                        .filter(|p| p.peer_id == self.target)
                        .flat_map(|p| p.addrs.iter().cloned())
                        .collect();
                    if !target_addrs.is_empty() {
                        self.note_target_addresses(
                            "closest-peers response",
                            target_addrs,
                        );
                    }

                    // Replace immediately so concurrency stays at MAX_QUERIES.
                    self.top_up_queries();
                }

                KademliaEvent::RoutingUpdated {
                    peer, addresses, ..
                } => {
                    let addrs = addresses.into_vec();
                    if peer == self.target {
                        self.note_target_addresses("RoutingUpdated", addrs.iter().cloned());
                    }
                    for addr in &addrs {
                        self.force_dial(peer, addr.clone());
                    }
                    match self.discovered_with_addresses.entry(peer) {
                        Entry::Occupied(mut occupied) => {
                            occupied.get_mut().extend(addrs);
                        }
                        Entry::Vacant(vacant) => {
                            vacant.insert(addrs.into_iter().collect());
                        }
                    };
                }

                KademliaEvent::RoutablePeer { peer, address }
                | KademliaEvent::PendingRoutablePeer { peer, address } => {
                    if peer == self.target {
                        self.note_target_addresses(
                            "RoutablePeer",
                            std::iter::once(address.clone()),
                        );
                    }
                    self.force_dial(peer, address.clone());
                    match self.discovered_with_addresses.entry(peer) {
                        Entry::Occupied(mut occupied) => {
                            occupied.get_mut().insert(address);
                        }
                        Entry::Vacant(vacant) => {
                            let mut set = HashSet::new();
                            set.insert(address);
                            vacant.insert(set);
                        }
                    };
                }
                _ => (),
            },

            SwarmEvent::Behaviour(BehaviourEvent::PeerInfo(info_event)) => match info_event {
                PeerInfoEvent::Identified { peer_id, info } => {
                    if peer_id == self.target {
                        log::info!(
                            "Identified TARGET peer={peer_id} agent={} protocol={}",
                            info.agent_version,
                            info.protocol_version
                        );
                        self.target_identified = true;
                    } else {
                        log::debug!("Identified peer_id={:?} info={:?}", peer_id, info);
                    }
                    self.peer_details.insert(peer_id, info);
                }
            },

            SwarmEvent::Behaviour(BehaviourEvent::Notifications(
                NotificationsToSwarm::CustomProtocolOpen {
                    peer_id,
                    received_handshake,
                    ..
                },
            )) => {
                if let Ok(role) = ProtocolRole::decode(&mut &received_handshake[..]) {
                    log::debug!("Identified peer_id={:?} role={:?}", peer_id, role);
                    self.peer_role.insert(peer_id, role);
                }
            }

            _ => (),
        }
    }
}

pub async fn discover_peer(
    url: String,
    peer: String,
    genesis: Option<String>,
    bootnodes: Vec<String>,
    identified: bool,
    timeout: Duration,
    query_timeout: Duration,
) -> Result<(), Box<dyn Error>> {
    let target: PeerId = peer
        .parse()
        .map_err(|e| format!("Invalid --peer `{peer}`: {e}"))?;

    let rpc_url = Url::parse(&url)?;

    let genesis = match genesis {
        Some(g) => g,
        None => {
            println!("       No genesis hash provided, fetching from RPC...");
            let hash = fetch_genesis_hash(rpc_url.clone()).await?;
            println!("       Genesis hash: 0x{}", hash);
            hash
        }
    };

    let bootnodes = resolve_bootnodes(&rpc_url, bootnodes, &mut std::io::stdout()).await?;

    let swarm = build_swarm(genesis.clone(), bootnodes, query_timeout).await?;
    let mut peer_discovery = PeerDiscovery::new(target, swarm);

    println!("Hunting peer {target} via aggressive target-keyed DHT queries...");

    let _ = tokio::time::timeout(timeout, peer_discovery.drive_events()).await;

    println!();
    println!("=== discover-peer summary ===");
    println!("target:                    {target}");
    println!("identified target:         {}", peer_discovery.target_identified);
    println!(
        "DHT reports for target:    {} (other peers told us about the target)",
        peer_discovery.target_dht_reports
    );
    println!(
        "addresses known for target: {} (learned via DHT, regardless of dial result)",
        peer_discovery.target_known_addresses.len()
    );
    println!(
        "peers seen via DHT:        {}",
        peer_discovery.discovered_with_addresses.len()
    );
    println!(
        "peers identified:          {}",
        peer_discovery.peer_details.len()
    );
    println!(
        "addresses dialed:          {}",
        peer_discovery.dialed_addresses.len()
    );

    if !peer_discovery.target_known_addresses.is_empty() {
        println!();
        println!("Addresses learned for target {target}:");
        for addr in &peer_discovery.target_known_addresses {
            println!("  {addr}");
        }
    }

    if let Some(info) = peer_discovery.peer_details.get(&target) {
        println!();
        println!("Identify info for target {target}:");
        println!("  Agent Version:    {}", info.agent_version);
        println!("  Protocol Version: {}", info.protocol_version);
        println!("  Observed Address: {}", info.observed_addr);
        println!("  Listen Addresses:");
        for addr in &info.listen_addrs {
            println!("    {addr}");
        }
        println!("  Protocols:");
        for proto in &info.protocols {
            println!("    {proto}");
        }
        if let Some(role) = peer_discovery.peer_role.get(&target) {
            println!("  Announced Role:   {role:?}");
        }
    }

    if identified {
        println!();
        println!(
            "Identified peers (responded to identify) num={}",
            peer_discovery.peer_details.len()
        );
        for (peer, info) in &peer_discovery.peer_details {
            let role = peer_discovery.peer_role.get(peer);
            println!(
                "identified={peer} version={:?} role={:?}",
                info.agent_version, role
            );
        }
    }

    Ok(())
}
