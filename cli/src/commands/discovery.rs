// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use crate::utils::{build_swarm, is_public_address, Location, Locator};
use codec::Decode;
use futures::StreamExt;
use libp2p::{
    identify::Info,
    kad::{GetClosestPeersError, GetClosestPeersOk, KademliaEvent, QueryId, QueryResult},
    multiaddr::Protocol,
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use std::time::Duration;
use std::{cmp::Reverse, error::Error};
use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    net::IpAddr,
};
use subp2p_explorer::{
    notifications::{behavior::NotificationsToSwarm, messages::ProtocolRole},
    peer_behavior::PeerInfoEvent,
    Behaviour, BehaviourEvent,
};
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

struct NetworkDiscovery {
    /// Drive the network behavior.
    swarm: Swarm<Behaviour>,
    /// In flight kademlia queries.
    queries: HashSet<QueryId>,
    /// Discovered peers by kademlia queries.
    discovered_with_addresses: HashMap<PeerId, HashSet<Multiaddr>>,
    /// Peer details including protocols, multiaddress.
    peer_details: HashMap<PeerId, Info>,
    /// Peers that announced their role.
    peer_role: HashMap<PeerId, ProtocolRole>,
    /// Peers dialed.
    dialed_peers: HashMap<PeerId, usize>,
}

impl NetworkDiscovery {
    /// Constructs a new [`NetworkDiscovery`].
    pub fn new(swarm: Swarm<Behaviour>) -> Self {
        Self {
            swarm,
            queries: HashSet::with_capacity(1024),
            discovered_with_addresses: HashMap::with_capacity(1024),
            peer_details: HashMap::with_capacity(1024),
            peer_role: HashMap::with_capacity(1024),
            dialed_peers: HashMap::with_capacity(1024),
        }
    }

    /// Insert a number of queries to randomly walk the DHT.
    ///
    /// Performs a Kademlia query that returns a number of closest peers up to
    /// the replication factor (k = 20 for substrate chains).
    fn insert_queries(&mut self, num: usize) {
        for _ in 0..num {
            self.queries.insert(
                self.swarm
                    .behaviour_mut()
                    .discovery
                    .get_closest_peers(PeerId::random()),
            );
        }
    }

    /// Track the dialed peers in response of an [`SwarmEvent::Dialing`] event.
    fn dialed_peer(&mut self, peer_id: Option<PeerId>) {
        // Record how many times have we dialed a peer.
        let Some(peer_id) = peer_id else { return };

        self.dialed_peers
            .entry(peer_id)
            .and_modify(|num| *num += 1)
            .or_insert(0);
    }

    /// Drive the network behavior events.
    pub async fn drive_events(&mut self) {
        // Start by performing 128 queries.
        self.insert_queries(128);

        let mut old_log_time = std::time::Instant::now();

        loop {
            let event = self.swarm.select_next_some().await;

            match event {
                SwarmEvent::Dialing { peer_id, .. } => {
                    self.dialed_peer(peer_id);
                }

                SwarmEvent::Behaviour(BehaviourEvent::Discovery(event)) => match event {
                    KademliaEvent::OutboundQueryProgressed {
                        id,
                        result: QueryResult::GetClosestPeers(result),
                        ..
                    } => {
                        self.queries.remove(&id);

                        // It might be possible that the query did not finish in 5 minutes.
                        // However we capture the provided peers.
                        // Peers are later reported by kademila events handled below.
                        let peers = match result {
                            Ok(GetClosestPeersOk { peers, .. }) => peers,
                            Err(GetClosestPeersError::Timeout { peers, .. }) => peers,
                        };
                        let num_discovered = peers.len();

                        let now = std::time::Instant::now();
                        if now.duration_since(old_log_time) > Duration::from_secs(10) {
                            old_log_time = now;
                            log::info!("...Discovery in progress last_query_num={num_discovered}");
                        }

                        if self.queries.is_empty() {
                            self.insert_queries(128);
                        }
                    }

                    KademliaEvent::RoutingUpdated {
                        peer, addresses, ..
                    } => {
                        match self.discovered_with_addresses.entry(peer) {
                            Entry::Occupied(mut occupied) => {
                                occupied.get_mut().extend(addresses.into_vec());
                            }
                            Entry::Vacant(vacant) => {
                                vacant.insert(addresses.iter().cloned().collect());
                            }
                        };
                    }

                    KademliaEvent::RoutablePeer { peer, address }
                    | KademliaEvent::PendingRoutablePeer { peer, address } => {
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
                        log::debug!("Identified peer_id={:?} info={:?}", peer_id, info);
                        self.peer_details.insert(peer_id, info);
                    }
                },

                SwarmEvent::Behaviour(BehaviourEvent::Notifications(
                    NotificationsToSwarm::CustomProtocolOpen {
                        peer_id,
                        index,
                        received_handshake,
                        inbound,
                        ..
                    },
                )) => {
                    if let Ok(role) = ProtocolRole::decode(&mut &received_handshake[..]) {
                        log::debug!("Identified peer_id={:?} role={:?}", peer_id, role);
                        self.peer_role.insert(peer_id, role);
                    }

                    log::debug!(
                        "Protocol open peer={:?} index={:?} handshake={:?} inbound={:?}",
                        peer_id,
                        index,
                        received_handshake,
                        inbound
                    );
                }

                _ => (),
            }
        }
    }
}

pub async fn discover_network(
    genesis: String,
    bootnodes: Vec<String>,
    num_cities: Option<usize>,
    raw_geolocation: bool,
    only_authorities: bool,
    timeout: std::time::Duration,
) -> Result<(), Box<dyn Error>> {
    let swarm = build_swarm(genesis.clone(), bootnodes)?;
    let mut network_discovery = NetworkDiscovery::new(swarm);

    // Drive network events for a few minutes.
    let _ = tokio::time::timeout(timeout, network_discovery.drive_events()).await;

    println!("Dialed num={} peers", network_discovery.dialed_peers.len());
    println!(
        "Discovered num={} peers",
        network_discovery.discovered_with_addresses.len()
    );

    let infos: HashMap<_, _> = network_discovery
        .peer_details
        .iter()
        .filter(|(_peer, info)| {
            info.protocols
                .iter()
                .any(|stream_proto| stream_proto.as_ref().contains(&genesis))
        })
        .collect();

    println!(
        "Peers with identity num={}",
        network_discovery.peer_details.len()
    );
    println!("Peers that support our genesis hash {:?}", infos.len());

    let peers_with_public_addr: HashMap<_, _> = infos
        .iter()
        .filter(|(_peer, info)| info.listen_addrs.iter().any(is_public_address))
        .collect();
    println!(
        "  Peers with public addresses {:?}",
        peers_with_public_addr.len()
    );
    println!(
        "  Peers with private addresses {:?}",
        infos.len() - peers_with_public_addr.len()
    );

    println!(
        "Peers with role associated num={}",
        network_discovery.peer_role.len()
    );

    if only_authorities {
        let authorities = network_discovery
            .peer_role
            .iter()
            .filter_map(|(peer, role)| {
                if *role == ProtocolRole::Authority {
                    Some(peer)
                } else {
                    None
                }
            });

        for peer in authorities {
            println!(
                "authority={peer} version={:?}",
                network_discovery
                    .peer_details
                    .get(peer)
                    .map(|info| info.agent_version.clone())
            );
        }
    }

    let locator = Locator::new();
    let mut cities: HashMap<String, usize> = HashMap::new();
    let mut geolocated_peers: HashMap<PeerId, Location> = HashMap::new();

    // Resolver for DNS addresses.
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    for (peer, info) in infos {
        for addr in &info.listen_addrs {
            let located = match addr.iter().next() {
                Some(Protocol::Ip4(ip)) => locator.locate(IpAddr::V4(ip)),
                Some(Protocol::Ip6(ip)) => locator.locate(IpAddr::V6(ip)),
                Some(Protocol::Dns(dns))
                | Some(Protocol::Dns4(dns))
                | Some(Protocol::Dns6(dns)) => {
                    let Ok(lookup) = resolver.lookup_ip(dns.to_string()).await else {
                        continue;
                    };

                    lookup.iter().find_map(|ip| locator.locate(ip))
                }
                _ => continue,
            };

            let Some(located) = located else { continue };

            cities
                .entry(located.city.clone())
                .and_modify(|num| *num += 1)
                .or_insert(1);

            geolocated_peers.insert(peer.clone(), located);

            break;
        }
    }

    // Print top k cities.
    let mut cities: Vec<_> = cities.iter().collect();
    cities.sort_by_key(|data| Reverse(*data.1));
    let iter = cities.iter().take(num_cities.unwrap_or(10));
    for (city, count) in iter {
        println!("   City={city} peers={count}");
    }

    if raw_geolocation {
        println!();

        for (peer, location) in geolocated_peers {
            println!("   Peer {peer}: {location:?}");
        }
    }

    Ok(())
}
