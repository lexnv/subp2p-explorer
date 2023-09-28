// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use subp2p_explorer::{
    discovery::DiscoveryBuilder,
    notifications::{
        behavior::{Notifications, NotificationsToSwarm, ProtocolsData},
        messages::ProtocolRole,
    },
    peer_behavior::{PeerBehaviour, PeerInfoEvent},
    transport::{TransportBuilder, MIB},
    Behaviour, BehaviourEvent, TRANSACTIONS_INDEX,
};

use clap::Parser as ClapParser;
use futures::StreamExt;
use libp2p::{
    identify::Info,
    identity,
    kad::{GetClosestPeersError, GetClosestPeersOk, KademliaEvent, QueryId, QueryResult},
    swarm::{SwarmBuilder, SwarmEvent},
    Multiaddr, PeerId, Swarm,
};
use primitive_types::H256;
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::error::Error;
use std::time::Duration;

/// Command for interacting with the CLI.
#[derive(Debug, ClapParser)]
enum Command {
    SendExtrinisic(SendExtrinisicOpts),
    DiscoverNetwork(DiscoverNetworkOpts),
}

/// Send extrinsic on the p2p network.
#[derive(Debug, ClapParser)]
pub struct SendExtrinisicOpts {
    /// Hex-encoded genesis hash of the chain.
    ///
    /// For example, "781e4046b4e8b5e83d33dde04b32e7cb5d43344b1f19b574f6d31cbbd99fe738"
    #[clap(long, short)]
    genesis: String,
    /// Bootnodes of the chain, must contain a multiaddress together with the peer ID.
    /// For example, "/ip4/127.0.0.1/tcp/30333/ws/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp".
    #[clap(long, use_value_delimiter = true, value_parser)]
    bootnodes: Vec<String>,
    /// Hex-encoded scale-encoded vector of extrinsics to submit to peers.
    #[clap(long, short)]
    extrinsics: String,
}

/// Discover the p2p network.
#[derive(Debug, ClapParser)]
pub struct DiscoverNetworkOpts {
    /// Hex-encoded genesis hash of the chain.
    ///
    /// For example, "781e4046b4e8b5e83d33dde04b32e7cb5d43344b1f19b574f6d31cbbd99fe738"
    #[clap(long, short)]
    genesis: String,
    /// Bootnodes of the chain, must contain a multiaddress together with the peer ID.
    /// For example, "/ip4/127.0.0.1/tcp/30333/ws/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp".
    #[clap(long, use_value_delimiter = true, value_parser)]
    bootnodes: Vec<String>,
}

fn build_swarm(
    genesis: String,
    bootnodes: Vec<String>,
) -> Result<Swarm<Behaviour>, Box<dyn Error>> {
    // Create a random key for ourselves.
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    tracing::info!("Local peer ID {:?}", local_peer_id);

    let genesis = genesis.trim_start_matches("0x");

    // Parse the provided bootnodes as `PeerId` and `MultiAddress`.
    let bootnodes: Vec<_> = bootnodes
        .iter()
        .map(|bootnode| {
            let parts: Vec<_> = bootnode.split('/').collect();
            let peer = parts.last().expect("Valid bootnode has peer; qed");
            let multiaddress: Multiaddr = bootnode.parse().expect("Valid multiaddress; qed");
            let peer_id: PeerId = peer.parse().expect("Valid peer ID; qed");

            log::info!("Bootnode peer={:?}", peer_id);
            (peer_id, multiaddress)
        })
        .collect();

    // Craft the specific protocol data.
    let protocol_data = ProtocolsData {
        genesis_hash: H256::from_slice(hex::decode(genesis)?.as_slice()),
        node_role: ProtocolRole::FullNode,
    };

    // Create a Switch (swarm) to manage peers and events.
    let mut swarm: Swarm<Behaviour> = {
        let transport = TransportBuilder::new()
            .yamux_maximum_buffer_size(256 * MIB)
            .build(local_key.clone());

        let discovery = DiscoveryBuilder::new()
            .record_ttl(Some(Duration::from_secs(0)))
            .provider_ttl(Some(Duration::from_secs(0)))
            .query_timeout(Duration::from_secs(5 * 60))
            .build(local_peer_id, genesis);

        let peer_info = PeerBehaviour::new(local_key.public());
        let notifications = Notifications::new(protocol_data);

        let behavior = Behaviour {
            notifications,
            peer_info,
            discovery,
        };

        SwarmBuilder::with_tokio_executor(transport, behavior, local_peer_id).build()
    };

    // Active set of peers from the kbuckets of kademlia.
    // These are the initial peers for which the queries are performed against.
    for (peer, multiaddress) in &bootnodes {
        swarm
            .behaviour_mut()
            .discovery
            .add_address(peer, multiaddress.clone());
    }

    Ok(swarm)
}

async fn submit_extrinsics(
    genesis: String,
    bootnodes: Vec<String>,
    extrinsics: String,
) -> Result<(), Box<dyn Error>> {
    let mut swarm = build_swarm(genesis, bootnodes)?;
    let payload = hex::decode(extrinsics.trim_start_matches("0x"))?;

    // Perform the kademlia bootstrap.
    let local_peer_id = swarm.local_peer_id().clone();
    let _query_id = swarm
        .behaviour_mut()
        .discovery
        .get_closest_peers(local_peer_id);

    // Keep track of protocol handlers to submit messages.
    let mut protocol_senders = HashMap::new();
    // Close after 30 notifications.
    let mut close_after = 30;
    loop {
        let event = swarm.select_next_some().await;

        match event {
            SwarmEvent::Behaviour(BehaviourEvent::Notifications(tx)) => match tx {
                NotificationsToSwarm::CustomProtocolOpen {
                    peer_id,
                    received_handshake,
                    inbound,
                    index,
                    sender,
                } => {
                    log::info!(
                        "Protocol open peer={:?} index={:?} handshake={:?} inbound={:?}",
                        peer_id,
                        received_handshake,
                        inbound,
                        index
                    );

                    protocol_senders.insert((peer_id, index), sender);
                }
                NotificationsToSwarm::CustomProtocolClosed { peer_id, index } => {
                    log::info!("Protocol closed peer={:?} index={:?}", peer_id, index);
                }
                NotificationsToSwarm::Notification {
                    peer_id,
                    message,
                    index,
                } => {
                    if close_after == 0 {
                        break;
                    }
                    close_after -= 1;

                    log::info!(
                        "Protocol notification peer={:?} index={:?} message={:?}",
                        index,
                        peer_id,
                        message
                    );

                    if let Some(sender) = protocol_senders.get_mut(&(peer_id, TRANSACTIONS_INDEX)) {
                        log::info!("Submit transaction for peer={:?}", peer_id);

                        let _ = sender.start_send(payload.clone());
                    }
                }
            },
            SwarmEvent::Behaviour(BehaviourEvent::PeerInfo(info_event)) => match info_event {
                PeerInfoEvent::Identified { peer_id, info } => {
                    log::info!("Peer identified peer_id={:?} info={:?}", peer_id, info);
                }
            },

            _ => (),
        }
    }

    Ok(())
}

struct NetworkDiscovery {
    /// Drive the network behavior.
    swarm: Swarm<Behaviour>,
    /// In flight kademlia queries.
    queries: HashSet<QueryId>,
    /// Discovered peers by kademlia queries.
    discovered_with_addresses: HashMap<PeerId, HashSet<Multiaddr>>,
    /// Peer details including protocols, multiaddress.
    peer_details: HashMap<PeerId, Info>,
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

                _ => (),
            }
        }
    }
}

async fn discover_network(genesis: String, bootnodes: Vec<String>) -> Result<(), Box<dyn Error>> {
    let swarm = build_swarm(genesis.clone(), bootnodes)?;
    let mut network_discovery = NetworkDiscovery::new(swarm);

    // Drive network events for 3 minutes.
    let _ = tokio::time::timeout(
        Duration::from_secs(3 * 60),
        network_discovery.drive_events(),
    )
    .await;

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
                .find(|stream_proto| stream_proto.as_ref().contains(&genesis))
                .is_some()
        })
        .collect();

    println!(
        "Peers with identity num={}",
        network_discovery.peer_details.len()
    );
    println!("Peers that support our genesis hash {:?}", infos.len());

    println!("Dialed num={} peers", network_discovery.dialed_peers.len());

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt().init();

    let args = Command::parse();
    match args {
        Command::SendExtrinisic(opts) => {
            submit_extrinsics(opts.genesis, opts.bootnodes, opts.extrinsics).await
        }
        Command::DiscoverNetwork(opts) => discover_network(opts.genesis, opts.bootnodes).await,
    }
}
