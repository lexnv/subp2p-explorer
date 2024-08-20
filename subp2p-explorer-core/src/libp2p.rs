use futures::{Stream, StreamExt};

use async_trait::async_trait;
use libp2p::{
    identify::{Behaviour as Identify, Config as IdentifyConfig, Event as IdentifyEvent},
    kad::{
        store::MemoryStore, Behaviour as Kademlia, Event as KademliaEvent, GetClosestPeersError,
        QueryResult,
    },
    ping::Behaviour as Ping,
    swarm::NetworkBehaviour,
    StreamProtocol,
};

use std::{collections::HashMap, sync::atomic::AtomicUsize, task::Poll};

use crate::{
    types::{multiaddr::Multiaddr, peer_id::PeerId},
    NetworkEvent, QueryId,
};

type SwarmEvent = libp2p::swarm::SwarmEvent<BehaviourEvent>;

pub struct Libp2pBackend {
    rx: tokio::sync::mpsc::Receiver<SwarmEvent>,
    command_tx: tokio::sync::mpsc::Sender<InnerCommand>,

    query_translate: HashMap<libp2p::kad::QueryId, QueryId>,
    peer_addresses: HashMap<libp2p::PeerId, Vec<libp2p::Multiaddr>>,
    next_query_id: AtomicUsize,
}

/// Network behavior for subtrate based chains.
#[derive(NetworkBehaviour)]
pub struct Behaviour {
    /// Periodically ping nodes, and close the connection if it's unresponsive.
    ping: Ping,
    /// Periodically identifies the remote and responds to incoming requests.
    identify: Identify,
    /// Discovers nodes of the network.
    discovery: Kademlia<MemoryStore>,
}

// const YAMUX_WINDOW_SIZE: u32 = 256 * 1024;
// const YAMUX_MAXIMUM_BUFFER_SIZE: usize = 16 * 1024 * 1024;

impl Libp2pBackend {
    pub async fn new(genesis: String) -> Self {
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = libp2p::PeerId::from(local_key.public());

        let genesis = genesis.trim_start_matches("0x");
        let kad_protocol = format!("/{}/kad", genesis);

        let mut disc_config =
            libp2p::kad::Config::new(StreamProtocol::try_from_owned(kad_protocol).unwrap());
        disc_config.set_max_packet_size(8192);
        disc_config.set_record_ttl(None);
        disc_config.set_provider_record_ttl(None);
        disc_config.set_query_timeout(std::time::Duration::from_secs(10));
        let store = MemoryStore::new(local_peer_id.clone());
        let discovery = Kademlia::with_config(local_peer_id.clone(), store, disc_config);

        let identify_config = IdentifyConfig::new("subp2p-explorer-0.1".into(), local_key.public())
            .with_cache_size(0);
        let identify = Identify::new(identify_config);

        let ping = Ping::new(Default::default());

        let behavior = Behaviour {
            ping,
            identify,
            discovery,
        };

        use libp2p::tcp::Config as TcpConfig;

        let tcp_config = TcpConfig::new().nodelay(true);
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp_config,
                libp2p_noise::Config::new,
                libp2p_yamux::Config::default,
            )
            .expect("Can construct TCP; qed")
            .with_dns()
            .expect("Can construct DNS; qed")
            .with_websocket(libp2p_noise::Config::new, libp2p_yamux::Config::default)
            .await
            .expect("Can construct websocket; qed")
            .with_behaviour(|_key| behavior)
            .expect("Can construct behaviour; qed")
            .build();

        let (tx, rx) = tokio::sync::mpsc::channel(1024 * 1024);
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel(512);

        tokio::spawn(async move {
            fn handle_cmd(swarm: &mut libp2p::Swarm<Behaviour>, cmd: InnerCommand) {
                log::trace!("[background] command {:?}", cmd);

                match cmd {
                    InnerCommand::AddKnownAddress { peer_id, address } => {
                        swarm
                            .behaviour_mut()
                            .discovery
                            .add_address(&peer_id, address);
                    }
                    InnerCommand::FindNode { peer_id, query_id } => {
                        let id = swarm.behaviour_mut().discovery.get_closest_peers(peer_id);
                        query_id.send(id).expect("Query ID should be received");
                    }
                }
            }

            async fn handle_swarm_event(
                tx: &tokio::sync::mpsc::Sender<SwarmEvent>,
                event: SwarmEvent,
            ) -> bool {
                log::trace!("[background] swarm event {:?}", event);
                if tx.send(event).await.is_err() {
                    return true;
                }
                false
            }

            loop {
                tokio::select! {
                    event = command_rx.recv() => {
                        handle_cmd(&mut swarm, event.unwrap());
                    },

                    event = swarm.select_next_some() => {
                        if handle_swarm_event(&tx, event).await {
                            break;
                        }
                    },
                }
            }
        });

        Self {
            rx,
            command_tx,

            query_translate: HashMap::new(),
            next_query_id: AtomicUsize::new(0),
            peer_addresses: HashMap::new(),
        }
    }
}

#[derive(Debug)]
enum InnerCommand {
    AddKnownAddress {
        peer_id: libp2p::PeerId,
        address: libp2p::Multiaddr,
    },
    FindNode {
        peer_id: libp2p::PeerId,
        query_id: tokio::sync::oneshot::Sender<libp2p::kad::QueryId>,
    },
}

#[async_trait]
impl crate::NetworkBackend for Libp2pBackend {
    async fn find_node(&mut self, peer: PeerId) -> QueryId {
        let peer_id: libp2p::PeerId = peer.into();

        let (tx, rx) = tokio::sync::oneshot::channel();
        let find_node = InnerCommand::FindNode {
            peer_id,
            query_id: tx,
        };

        self.command_tx
            .send(find_node)
            .await
            .expect("Backend task closed; this should never happen");

        let query = rx.await.expect("Query ID should be received");
        log::info!("find_node {:?}", query);

        let query_id = self
            .next_query_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.query_translate.insert(query, QueryId(query_id));

        QueryId(query_id)
    }

    async fn add_known_peer(&mut self, peer_id: PeerId, address: Vec<Multiaddr>) {
        log::info!("add_known_peer {:?} at {:?}", peer_id, address);
        let peer_id: libp2p::PeerId = peer_id.into();

        for addr in address {
            let addr: libp2p::Multiaddr = addr.into();
            let command = InnerCommand::AddKnownAddress {
                peer_id,
                address: addr,
            };

            self.command_tx
                .send(command)
                .await
                .expect("Backend task closed; this should never happen");
        }
    }
}

impl Stream for Libp2pBackend {
    type Item = NetworkEvent;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> Poll<Option<Self::Item>> {
        let this = std::pin::Pin::into_inner(self);

        let result = this.rx.poll_recv(cx);
        let event = match result {
            Poll::Ready(Some(event)) => event,
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Pending => return Poll::Pending,
        };

        log::trace!("libp2p event {:?}", event);

        match event {
            libp2p::swarm::SwarmEvent::Behaviour(event) => match event {
                BehaviourEvent::Identify(IdentifyEvent::Received { peer_id, info, .. }) => {
                    return Poll::Ready(Some(NetworkEvent::PeerIdentified {
                        peer: peer_id.into(),
                        protocol_version: Some(info.protocol_version),
                        user_agent: Some(info.agent_version),
                        supported_protocols: info
                            .protocols
                            .into_iter()
                            .map(|p| p.to_string())
                            .collect(),
                        observed_address: info.observed_addr.into(),
                        listen_addresses: info.listen_addrs.into_iter().map(Into::into).collect(),
                    }));
                }
                BehaviourEvent::Discovery(event) => match event {
                    KademliaEvent::OutboundQueryProgressed {
                        id,
                        result: QueryResult::GetClosestPeers(result),
                        ..
                    } => {
                        let (key, peers) = match result {
                            Ok(res) => (res.key, res.peers),
                            Err(GetClosestPeersError::Timeout { key, peers }) => (key, peers),
                        };

                        // Get the subp2p query ID.
                        let query_id = this.query_translate.remove(&id).unwrap();

                        return Poll::Ready(Some(NetworkEvent::FindNode {
                            query_id,
                            target: PeerId::from_bytes(key.as_ref()).unwrap(),
                            peers: peers
                                .into_iter()
                                .map(|peer_id| {
                                    (
                                        peer_id.peer_id.into(),
                                        peer_id.addrs.into_iter().map(Into::into).collect(),
                                    )
                                })
                                .collect(),
                        }));
                    }

                    // Collect addresses during discovery.
                    KademliaEvent::RoutablePeer { peer, address }
                    | KademliaEvent::PendingRoutablePeer { peer, address } => {
                        this.peer_addresses
                            .entry(peer)
                            .or_insert_with(Vec::new)
                            .push(address);
                    }
                    KademliaEvent::RoutingUpdated {
                        peer, addresses, ..
                    } => {
                        this.peer_addresses
                            .entry(peer)
                            .or_insert_with(Vec::new)
                            .extend(addresses.into_vec());
                    }
                    _ => (),
                },
                _ => (),
            },
            _ => (),
        };

        // Since we are only interested in some events from the backend,
        // we need to wake up the task again to poll for more events.
        // Otherwise, we would be stuck in the pending state since no external
        // event will ever call cx.waker().wake_by_ref() again.
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
