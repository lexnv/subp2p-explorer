use futures::{future::BoxFuture, stream::FuturesUnordered, Stream, StreamExt};
use std::task::Poll;

use crate::{
    types::{multiaddr::Multiaddr, peer_id::PeerId},
    QueryId,
};
use async_trait::async_trait;

use litep2p::{
    config::ConfigBuilder,
    protocol::libp2p::{
        identify::{Config as IdentifyConfig, IdentifyEvent},
        kademlia::{self, *},
        ping::{Config as PingConfig, PingEvent},
    },
    transport::tcp::config::Config as TcpConfig,
    Litep2p,
};

use crate::NetworkEvent;

pub struct Litep2pBackend {
    tx: tokio::sync::mpsc::Sender<InnerCommand>,
    kad_handle: KademliaHandle,
    ping_stream: Box<dyn Stream<Item = PingEvent> + Send + Unpin>,
    identify_stream: Box<dyn Stream<Item = IdentifyEvent> + Send + Unpin>,

    pending_actions: FuturesUnordered<BoxFuture<'static, ()>>,
}

enum InnerCommand {
    AddKnownAddress {
        peer_id: PeerId,
        address: Vec<Multiaddr>,
    },
    ListenAddresses {
        tx: tokio::sync::oneshot::Sender<Vec<Multiaddr>>,
    },
}

impl Litep2pBackend {
    pub fn new(genesis_hash: String) -> Self {
        let (ping_config, ping_event_stream) = PingConfig::default();

        // Genesis: 91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3.
        let (config, kad_handle) = kademlia::ConfigBuilder::new()
            .with_protocol_names(vec![format!("/{}/kad", genesis_hash).into()])
            // To set the routing table to manual use:
            .with_routing_table_update_mode(RoutingTableUpdateMode::Manual)
            .build();

        let (identify_config, identify_event_stream) = IdentifyConfig::new(
            "subp2p-explorer-0.1".into(),
            Some("subp2p-explorer".to_string()),
        );

        let litep2p_config = ConfigBuilder::new()
            // `litep2p` will bind to `/ip6/::1/tcp/0` by default
            .with_tcp(TcpConfig {
                listen_addresses: vec!["/ip6/::/tcp/0".parse().expect("valid address")],
                reuse_port: true,
                nodelay: true,
                ..Default::default()
            })
            .with_websocket(Default::default())
            .with_libp2p_ping(ping_config)
            .with_libp2p_kademlia(config)
            .with_libp2p_identify(identify_config)
            .build();

        let mut litep2p = Litep2p::new(litep2p_config).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(32);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = rx.recv() => {
                        match event {
                            Some(InnerCommand::AddKnownAddress { peer_id, address }) => {
                                litep2p.add_known_address(peer_id.into(), address.into_iter().map(Into::into));
                            },
                            Some(InnerCommand::ListenAddresses { tx }) => {
                                let _ = tx.send(litep2p.listen_addresses().cloned().map(Into::into).collect());
                            },
                            _ => return,
                        }
                    },

                    _ = litep2p.next_event() => {},
                }
            }
        });

        Litep2pBackend {
            tx,
            kad_handle,
            ping_stream: ping_event_stream,
            identify_stream: identify_event_stream,
            pending_actions: FuturesUnordered::new(),
        }
    }
}

#[async_trait]
impl crate::NetworkBackend for Litep2pBackend {
    async fn find_node(&mut self, peer: PeerId) -> QueryId {
        QueryId(self.kad_handle.find_node(peer.into()).await.0)
    }

    async fn add_known_peer(&mut self, peer_id: PeerId, address: Vec<Multiaddr>) {
        let _ = self
            .tx
            .send(InnerCommand::AddKnownAddress {
                peer_id,
                address: address.clone(),
            })
            .await
            .expect("Backend task closed; this should never happen");

        self.kad_handle
            .add_known_peer(
                peer_id.into(),
                address.into_iter().map(Into::into).collect(),
            )
            .await;
    }

    async fn listen_addresses(&mut self) -> Vec<Multiaddr> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        let _ = self
            .tx
            .send(InnerCommand::ListenAddresses { tx })
            .await
            .expect("Backend task closed; this should never happen");

        rx.await
            .expect("Backend task closed; this should never happen")
    }

    fn poll_next_event(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> Poll<Option<NetworkEvent>> {
        self.poll_next(cx)
    }
}

impl Stream for Litep2pBackend {
    type Item = NetworkEvent;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> Poll<Option<Self::Item>> {
        let _ = self.ping_stream.poll_next_unpin(cx);

        if !self.pending_actions.is_empty() {
            let _ = self.pending_actions.poll_next_unpin(cx);
        }

        if let Poll::Ready(Some(event)) = self.identify_stream.poll_next_unpin(cx) {
            let IdentifyEvent::PeerIdentified {
                peer,
                protocol_version,
                user_agent,
                supported_protocols,
                observed_address,
                listen_addresses,
            } = event;

            let tx = self.tx.clone();
            let peer_id = peer.clone();
            let pending_listen_addresses: Vec<_> = listen_addresses
                .clone()
                .into_iter()
                .map(Into::into)
                .collect();

            self.pending_actions.push(Box::pin(async move {
                tx.send(InnerCommand::AddKnownAddress {
                    peer_id: peer_id.into(),
                    address: pending_listen_addresses,
                })
                .await
                .expect("Backend task closed; this should never happen");
            }));

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
            match event {
                KademliaEvent::FindNodeSuccess {
                    query_id,
                    target,
                    peers,
                } => {
                    return Poll::Ready(Some(NetworkEvent::FindNode {
                        query_id: crate::QueryId(query_id.0),
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

                KademliaEvent::RoutingTableUpdate { .. } => {}

                KademliaEvent::QueryFailed { query_id } => {
                    log::warn!("Query failed: {:?}", query_id)
                }

                _ => {
                    // Since we are only interested in some events from the backend,
                    // we need to wake up the task again to poll for more events.
                    // Otherwise, we would be stuck in the pending state since no external
                    // event will ever call cx.waker().wake_by_ref() again.
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
        }

        Poll::Pending
    }
}
