// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use crate::notifications::{
    handler::{
        NotificationsHandler, NotificationsHandlerFromBehavior, NotificationsHandlerToBehavior,
    },
    messages::BlockHash,
    messages::ProtocolRole,
};

use bytes::BytesMut;
use futures::channel::mpsc;
use libp2p::{
    core::{ConnectedPoint, Endpoint},
    swarm::{
        derive_prelude::ConnectionEstablished, ConnectionClosed, ConnectionDenied, ConnectionId,
        NetworkBehaviour, NotifyHandler, ToSwarm,
    },
    Multiaddr, PeerId,
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    task::{Poll, Waker},
};

const LOG_TARGET: &str = "subp2p-behavior";

/// The events emitted by this network behavior back to the swarm.
#[derive(Debug)]
pub enum NotificationsToSwarm {
    /// Opened a custom protocol with the remote.
    CustomProtocolOpen {
        /// Id of the peer we are connected to.
        peer_id: PeerId,
        /// The index of the protocol.
        index: usize,
        /// Handshake that was received.
        received_handshake: Vec<u8>,
        /// Is the connection inbound.
        inbound: bool,
        /// Channel to send data on this protocol.
        sender: mpsc::Sender<Vec<u8>>,
    },

    /// The given protocol has been closed.
    ///
    /// Any data captured from [`CustomProtocolOpen`] is stale (ie the sender).
    CustomProtocolClosed {
        /// Id of the peer we were connected to.
        peer_id: PeerId,
        /// The index of the protocol.
        index: usize,
    },

    /// A custom notification message has been received on the given protocol.
    Notification {
        /// Id of the peer the message came from.
        peer_id: PeerId,
        /// The index of the protocol.
        index: usize,
        /// Message that has been received.
        message: BytesMut,
    },
}

/// Data needed by supported notification protocols.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolsData {
    /// The genesis hash to construct the `block-announces` handshake.
    pub genesis_hash: BlockHash,

    /// The identity that we declare this peer.
    ///
    /// Substrate requires protocols that don't have a specific handshake to submit
    /// the node's role over the wire. Such is the case of the `/transactions/1` protocol.
    ///
    /// Note that `LightClients` will not receive any notifications on the transaction protocol
    /// to avoid resource consumption.
    pub node_role: ProtocolRole,
}

/// Handles the notifications protocols.
pub struct Notifications {
    /// Events to produce from `poll()` back to the swarm.
    ///
    /// Events that are populated by either `on_swarm_event` (triggered from the higher-level swarm component)
    /// or `on_connection_handler_event` (triggered when requesting a substream).
    events: VecDeque<ToSwarm<NotificationsToSwarm, NotificationsHandlerFromBehavior>>,
    /// Peer details for valid connections.
    peers_details: HashMap<PeerId, HashSet<ConnectionId>>,
    /// Data needed by protocols.
    data: ProtocolsData,
    /// Ensure we wake up on events. Set by the poll function.
    waker: Option<Waker>,
}

impl Notifications {
    /// Constructs a new [`Notifications`].
    pub fn new(data: ProtocolsData) -> Self {
        Notifications {
            events: VecDeque::with_capacity(16),
            peers_details: HashMap::default(),
            data,
            waker: None,
        }
    }

    /// Propagate an event back to the swarm.
    fn propagate_event(
        &mut self,
        event: ToSwarm<NotificationsToSwarm, NotificationsHandlerFromBehavior>,
    ) {
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }

        self.events.push_back(event);
    }
}

impl NetworkBehaviour for Notifications {
    type ConnectionHandler = NotificationsHandler;
    type ToSwarm = NotificationsToSwarm;

    fn handle_pending_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        Ok(())
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _maybe_peer: Option<PeerId>,
        _addresses: &[Multiaddr],
        _effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        Ok(Vec::new())
    }

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: libp2p::swarm::ConnectionId,
        peer: libp2p::PeerId,
        local_addr: &libp2p::Multiaddr,
        remote_addr: &libp2p::Multiaddr,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        log::info!(target: LOG_TARGET, "Notifications new inbound for peer={:?}", peer);

        let handler = NotificationsHandler::new(
            peer,
            ConnectedPoint::Listener {
                local_addr: local_addr.clone(),
                send_back_addr: remote_addr.clone(),
            },
            self.data.clone(),
        );

        Ok(handler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: libp2p::swarm::ConnectionId,
        peer: libp2p::PeerId,
        addr: &libp2p::Multiaddr,
        _role_override: libp2p::core::Endpoint,
    ) -> Result<libp2p::swarm::THandler<Self>, libp2p::swarm::ConnectionDenied> {
        log::info!(target: LOG_TARGET, "Notifications new outbound for peer={:?}", peer);

        let handler = NotificationsHandler::new(
            peer,
            ConnectedPoint::Dialer {
                role_override: Endpoint::Dialer,
                address: addr.clone(),
            },
            self.data.clone(),
        );

        Ok(handler)
    }

    fn on_swarm_event(&mut self, event: libp2p::swarm::FromSwarm<Self::ConnectionHandler>) {
        match event {
            libp2p::swarm::FromSwarm::ConnectionEstablished(ConnectionEstablished {
                peer_id,
                connection_id,
                ..
            }) => {
                log::debug!(target: LOG_TARGET,
                    "Notifications swarm connection established peer={:?} connection={:?}",
                    peer_id,
                    connection_id
                );

                self.peers_details
                    .entry(peer_id)
                    .and_modify(|entry| {
                        let _ = entry.insert(connection_id);
                    })
                    .or_insert_with(|| {
                        let mut hash = HashSet::new();
                        hash.insert(connection_id);
                        hash
                    });

                // Currently supports 2 protocols.
                for index in 0..2 {
                    self.propagate_event(ToSwarm::NotifyHandler {
                        peer_id,
                        handler: NotifyHandler::One(connection_id),
                        event: NotificationsHandlerFromBehavior::Open { index },
                    });
                }
            }
            libp2p::swarm::FromSwarm::ConnectionClosed(ConnectionClosed {
                peer_id,
                connection_id,
                ..
            }) => {
                log::debug!(target: LOG_TARGET,
                    "Notifications swarm connection closed peer={:?} connection={:?}",
                    peer_id,
                    connection_id
                );

                if let Some(details) = self.peers_details.get_mut(&peer_id) {
                    let removed = details.remove(&connection_id);
                    if !removed {
                        log::warn!(target: LOG_TARGET,
                            "Notifications swarm connection closed for untracked connection peer={:?} connection={:?}",
                            peer_id,
                            connection_id
                        );
                    }
                } else {
                    log::warn!(target: LOG_TARGET,
                        "Notifications swarm connection closed for untracked peer, peer={:?} connection={:?}",
                        peer_id,
                        connection_id
                    );
                }

                // Currently supports 2 protocols.
                for index in 0..2 {
                    self.propagate_event(ToSwarm::NotifyHandler {
                        peer_id,
                        handler: NotifyHandler::One(connection_id),
                        event: NotificationsHandlerFromBehavior::Close { index },
                    });
                }
            }
            _ => (),
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: libp2p::PeerId,
        connection_id: libp2p::swarm::ConnectionId,
        event: libp2p::swarm::THandlerOutEvent<Self>,
    ) {
        log::info!(target: LOG_TARGET,
            " Transactions::on_connection_handler_event peer {:?} {:?}",
            peer_id,
            event
        );

        match event {
            NotificationsHandlerToBehavior::HandshakeCompleted {
                index,
                handshake,
                is_inbound,
                sender,
                ..
            } => {
                log::debug!(target: LOG_TARGET,
                    "Notifications handler complited handshake peer={:?} connection={:?} index={:?} handshake={:?}",
                    peer_id,
                    connection_id,
                    index,
                    handshake,
                );

                self.propagate_event(ToSwarm::GenerateEvent(
                    NotificationsToSwarm::CustomProtocolOpen {
                        index,
                        peer_id,
                        received_handshake: handshake,
                        inbound: is_inbound,
                        sender,
                    },
                ));
            }
            NotificationsHandlerToBehavior::HandshakeError { index } => {
                log::debug!(target: LOG_TARGET,
                    "Notifications handler error handshake peer={:?} connection={:?} index={:?}",
                    peer_id,
                    connection_id,
                    index,
                );
            }
            NotificationsHandlerToBehavior::OpenDesiredByRemote { index } => {
                // Note: extend to reject protocols for specific peers in the future.
                self.propagate_event(ToSwarm::NotifyHandler {
                    peer_id,
                    handler: NotifyHandler::One(connection_id),
                    event: NotificationsHandlerFromBehavior::Open { index },
                });
            }
            NotificationsHandlerToBehavior::CloseDesired { index } => {
                self.propagate_event(ToSwarm::NotifyHandler {
                    peer_id,
                    handler: NotifyHandler::One(connection_id),
                    event: NotificationsHandlerFromBehavior::Close { index },
                });
            }
            NotificationsHandlerToBehavior::Close { .. } => {}
            NotificationsHandlerToBehavior::Notification { bytes, index } => {
                self.propagate_event(ToSwarm::GenerateEvent(NotificationsToSwarm::Notification {
                    peer_id,
                    index,
                    message: bytes,
                }));
            }
        }
    }

    fn poll(
        &mut self,
        cx: &mut std::task::Context<'_>,
        _params: &mut impl libp2p::swarm::PollParameters,
    ) -> std::task::Poll<ToSwarm<Self::ToSwarm, libp2p::swarm::THandlerInEvent<Self>>> {
        self.waker = Some(cx.waker().clone());

        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }

        Poll::Pending
    }
}
