pub mod types;

use futures::{Stream, StreamExt};
use std::collections::HashSet;

use types::{multiaddr::Multiaddr, peer_id::PeerId};

use std::task::Poll;

pub struct NetworkBackend {}

pub enum DhtEvent {}

/// Type representing a query ID.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct QueryId(usize);

use litep2p::{
    config::ConfigBuilder,
    protocol::libp2p::{
        identify::{Config as IdentifyConfig, IdentifyEvent},
        kademlia::{self, *},
        ping::{Config as PingConfig, PingEvent},
    },
    Litep2p,
};

pub enum NetworkEvent {
    /// A peer has been identified via `/identify` protocol.
    ///
    /// Event emitted if the `/identify` protocol is configured.
    PeerIdentified {
        /// Peer ID.
        peer: PeerId,

        /// Protocol version.
        protocol_version: Option<String>,

        /// User agent.
        user_agent: Option<String>,

        /// Supported protocols.
        supported_protocols: HashSet<String>,

        /// Observed address.
        observed_address: Multiaddr,

        /// Listen addresses.
        listen_addresses: Vec<Multiaddr>,
    },

    /// The result of a `find_node` query.
    FindNode {
        /// Query ID.
        query_id: QueryId,

        /// Target of the query
        target: PeerId,

        /// Found nodes and their addresses.
        peers: Vec<(PeerId, Vec<Multiaddr>)>,
    },
}

pub struct Litep2pBackend {
    inner: litep2p::Litep2p,

    kad_handle: KademliaHandle,
    ping_stream: Box<dyn Stream<Item = PingEvent> + Send + Unpin>,
    identify_stream: Box<dyn Stream<Item = IdentifyEvent> + Send + Unpin>,
}

impl Litep2pBackend {
    pub fn new(genesis_hash: String) -> Self {
        let (ping_config, ping_event_stream) = PingConfig::default();

        // Genesis: 91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3.
        let (config, kad_handle) = kademlia::ConfigBuilder::new()
            .with_protocol_names(vec![format!("/{}/kad", genesis_hash).into()])
            .build();

        let (identify_config, identify_event_stream) = IdentifyConfig::new(
            "subp2p-explorer-0.1".into(),
            Some("subp2p-explorer".to_string()),
            vec![],
        );

        let litep2p_config = ConfigBuilder::new()
            // `litep2p` will bind to `/ip6/::1/tcp/0` by default
            .with_tcp(Default::default())
            .with_websocket(Default::default())
            .with_libp2p_ping(ping_config)
            .with_libp2p_kademlia(config)
            .with_libp2p_identify(identify_config)
            .build();

        let litep2p = Litep2p::new(litep2p_config).unwrap();

        Litep2pBackend {
            inner: litep2p,
            kad_handle,
            ping_stream: ping_event_stream,
            identify_stream: identify_event_stream,
        }
    }
}

impl Stream for Litep2pBackend {
    type Item = NetworkEvent;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> Poll<Option<Self::Item>> {
        let _ = self.ping_stream.poll_next_unpin(cx);

        if let Poll::Ready(Some(event)) = self.identify_stream.poll_next_unpin(cx) {
            let IdentifyEvent::PeerIdentified {
                peer,
                protocol_version,
                user_agent,
                supported_protocols,
                observed_address,
                listen_addresses,
            } = event;

            return Poll::Ready(Some(NetworkEvent::PeerIdentified {
                peer: peer.into(),
                protocol_version,
                user_agent,
                supported_protocols: supported_protocols
                    .into_iter()
                    .map(|protocol| protocol.to_string())
                    .collect(),
                observed_address: observed_address.into(),
                listen_addresses: listen_addresses.into_iter().map(Into::into).collect(),
            }));
        }

        if let Poll::Ready(Some(event)) = self.kad_handle.poll_next_unpin(cx) {
            if let KademliaEvent::FindNodeSuccess {
                query_id,
                target,
                peers,
            } = event
            {
                return Poll::Ready(Some(NetworkEvent::FindNode {
                    query_id: QueryId(query_id.0),
                    target: target.into(),
                    peers: peers
                        .into_iter()
                        .map(|(peer_id, addresses)| {
                            (
                                peer_id.into(),
                                addresses.into_iter().map(Into::into).collect(),
                            )
                        })
                        .collect(),
                }));
            }
        }

        Poll::Pending
    }
}
