use futures::{Stream, StreamExt};

use libp2p::{
    identify::{Behaviour as Identify, Config as IdentifyConfig, Event as IdentifyEvent},
    kad::{
        store::MemoryStore, Behaviour as Kademlia, Config as KademliaConfig,
        Event as KademliaEvent, GetClosestPeersError, QueryResult,
    },
    ping::Behaviour as Ping,
    swarm::{NetworkBehaviour, SwarmBuilder},
    StreamProtocol,
};

use std::{collections::HashMap, sync::atomic::AtomicUsize, task::Poll};

use crate::{
    types::{multiaddr::Multiaddr, peer_id::PeerId},
    NetworkEvent, QueryId,
};

pub struct Libp2pBackend {
    inner: libp2p::Swarm<Behaviour>,

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

const YAMUX_WINDOW_SIZE: u32 = 256 * 1024;
const YAMUX_MAXIMUM_BUFFER_SIZE: usize = 16 * 1024 * 1024;

impl Libp2pBackend {
    fn transport(
        keypair: libp2p::identity::Keypair,
    ) -> libp2p::core::transport::Boxed<(libp2p::PeerId, libp2p::core::muxing::StreamMuxerBox)>
    {
        use libp2p::Transport;

        // The main transport is DNS(TCP).
        let tcp_config = libp2p::tcp::Config::new().nodelay(true);
        let tcp_trans = libp2p::tcp::tokio::Transport::new(tcp_config.clone());
        let dns = libp2p::dns::TokioDnsConfig::system(tcp_trans).expect("Can construct DNS; qed");

        // Support for WS and WSS.
        let tcp_trans = libp2p::tcp::tokio::Transport::new(tcp_config);
        let dns_for_wss =
            libp2p::dns::TokioDnsConfig::system(tcp_trans).expect("Valid config provided; qed");

        let transport = libp2p::websocket::WsConfig::new(dns_for_wss).or_transport(dns);

        let authentication_config =
            libp2p::noise::Config::new(&keypair).expect("Can create noise config; qed");

        let multiplexing_config = {
            let mut yamux_config = libp2p::yamux::Config::default();

            // Enable proper flow-control: window updates are only sent when
            // buffered data has been consumed.
            yamux_config.set_window_update_mode(libp2p::yamux::WindowUpdateMode::on_read());
            yamux_config.set_max_buffer_size(YAMUX_MAXIMUM_BUFFER_SIZE);
            yamux_config.set_receive_window_size(YAMUX_WINDOW_SIZE);

            yamux_config
        };

        transport
            .upgrade(libp2p::core::upgrade::Version::V1Lazy)
            .authenticate(authentication_config)
            .multiplex(multiplexing_config)
            .timeout(std::time::Duration::from_secs(20))
            .boxed()
    }

    pub fn new(genesis: String) -> Self {
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = libp2p::PeerId::from(local_key.public());

        let transport = Self::transport(local_key.clone());

        let genesis = genesis.trim_start_matches("0x");
        let kad_protocol = format!("/{}/kad", genesis);

        let mut discovery = KademliaConfig::default();
        discovery.set_max_packet_size(8192);
        discovery.set_record_ttl(None);
        discovery.set_provider_record_ttl(None);
        discovery.set_query_timeout(std::time::Duration::from_secs(60));
        discovery.set_protocol_names(vec![StreamProtocol::try_from_owned(kad_protocol).unwrap()]);

        let store = MemoryStore::new(local_peer_id.clone());
        let discovery = Kademlia::with_config(local_peer_id.clone(), store, discovery);

        let identify_config = IdentifyConfig::new("subp2p-explorer-0.1".into(), local_key.public())
            .with_cache_size(0);
        let identify = Identify::new(identify_config);

        let ping = Ping::new(Default::default());

        let behavior = Behaviour {
            ping,
            identify,
            discovery,
        };

        // TODO: The new API example is broken.
        // use libp2p::core::muxing::StreamMuxerBox;
        // use libp2p::core::transport::dummy::DummyTransport;
        // use libp2p::identity::PeerId;
        // use libp2p::{swarm::NetworkBehaviour, SwarmBuilder};
        // use std::error::Error;
        // libp2p::SwarmBuilder::with_existing_identity(local_key)
        //     .with_tokio()
        //     .with_tcp(
        //         TcpConfig::new().nodelay(true),
        //         (libp2p_tls::Config::new, libp2p_noise::Config::new),
        //         libp2p_yamux::Config::default,
        //     )
        //     .with_dns()
        //     .expect("Can construct DNS; qed")
        //     .with_websocket(
        //         (libp2p_tls::Config::new, libp2p_noise::Config::new),
        //         libp2p_yamux::Config::default,
        //     )
        //     .await
        //     .expect("Can construct websocket; qed")
        //     .with_behaviour(|_key, _relay| behavior)
        //     .build();

        Self {
            inner: libp2p::swarm::SwarmBuilder::with_tokio_executor(
                transport,
                behavior,
                local_peer_id,
            )
            .build(),

            query_translate: HashMap::new(),
            next_query_id: AtomicUsize::new(0),
            peer_addresses: HashMap::new(),
        }
    }

    pub async fn find_node(&mut self, peer: PeerId) -> QueryId {
        let peer_id: libp2p::PeerId = peer.into();

        let query = self
            .inner
            .behaviour_mut()
            .discovery
            .get_closest_peers(peer_id);

        let query_id = self
            .next_query_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.query_translate.insert(query, QueryId(query_id));

        QueryId(query_id)
    }

    pub async fn add_known_peer(
        &mut self,
        peer_id: PeerId,
        address: impl Iterator<Item = Multiaddr>,
    ) {
        let peer_id: libp2p::PeerId = peer_id.into();
        address.into_iter().map(Into::into).for_each(|address| {
            self.inner
                .behaviour_mut()
                .discovery
                .add_address(&peer_id, address);
        })
    }
}

impl Stream for Libp2pBackend {
    type Item = NetworkEvent;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> Poll<Option<Self::Item>> {
        match self.inner.poll_next_unpin(cx) {
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(event)) => match event {
                libp2p::swarm::SwarmEvent::Behaviour(event) => match event {
                    BehaviourEvent::Identify(IdentifyEvent::Received { peer_id, info, .. }) => {
                        Poll::Ready(Some(NetworkEvent::PeerIdentified {
                            peer: peer_id.into(),
                            protocol_version: Some(info.protocol_version),
                            user_agent: Some(info.agent_version),
                            supported_protocols: info
                                .protocols
                                .into_iter()
                                .map(|p| p.to_string())
                                .collect(),
                            observed_address: info.observed_addr.into(),
                            listen_addresses: info
                                .listen_addrs
                                .into_iter()
                                .map(Into::into)
                                .collect(),
                        }))
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
                            let query_id = self.query_translate.remove(&id).unwrap();

                            Poll::Ready(Some(NetworkEvent::FindNode {
                                query_id,
                                target: PeerId::from_bytes(key.as_ref()).unwrap(),
                                peers: peers
                                    .into_iter()
                                    .map(|peer_id| {
                                        let addresses = self
                                            .peer_addresses
                                            .get(&peer_id)
                                            .map(Clone::clone)
                                            .unwrap_or_default()
                                            .into_iter()
                                            .map(Into::into)
                                            .collect();
                                        (peer_id.into(), addresses)
                                    })
                                    .collect(),
                            }))
                        }

                        // Collect addresses during discovery.
                        KademliaEvent::RoutablePeer { peer, address }
                        | KademliaEvent::PendingRoutablePeer { peer, address } => {
                            self.peer_addresses
                                .entry(peer)
                                .or_insert_with(Vec::new)
                                .push(address);

                            Poll::Pending
                        }
                        KademliaEvent::RoutingUpdated {
                            peer, addresses, ..
                        } => {
                            self.peer_addresses
                                .entry(peer)
                                .or_insert_with(Vec::new)
                                .extend(addresses.into_vec());

                            Poll::Pending
                        }

                        _ => Poll::Pending,
                    },

                    _ => Poll::Pending,
                },
                _ => Poll::Pending,
            },
            _ => Poll::Pending,
        }
    }
}
