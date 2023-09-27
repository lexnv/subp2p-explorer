// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use std::{
    collections::HashSet,
    task::{Context, Poll},
};

use either::Either;
use fnv::FnvHashMap;
use libp2p::{
    core::{ConnectedPoint, Endpoint},
    identify::{
        Behaviour as Identify, Config as IdentifyConfig, Event as IdentifyEvent,
        Info as IdentifyInfo,
    },
    identity::PublicKey,
    ping::{Behaviour as Ping, Config as PingConfig},
    swarm::{
        behaviour::{
            AddressChange, ConnectionClosed, ConnectionEstablished, DialFailure, FromSwarm,
            ListenFailure,
        },
        ConnectionDenied, ConnectionHandler, ConnectionHandlerSelect, ConnectionId,
        NetworkBehaviour, PollParameters, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
    },
    Multiaddr, PeerId,
};

/// The agent client string of this crate.
pub const AGENT: &str = "subxt-p2p-agent";

/// Acurate p2p behavior as part of the substrate network.
///
/// Implements ping and identity as protocols under "/ipfs/ping/1.0.0" and "/substrate/1.0" (equivalent of "/ipfs/id/1.0.0").
///
/// Stores details about discovered peers.
pub struct PeerBehaviour {
    /// Periodically ping nodes, and close the connection if it's unresponsive.
    ping: Ping,
    /// Periodically identifies the remote and responds to incoming requests.
    identify: Identify,
    /// Information about the connected peers.
    details: FnvHashMap<PeerId, NodeDetails>,
    /// Track external addresses.
    external_addresses: HashSet<Multiaddr>,
}

impl PeerBehaviour {
    pub fn new(local_public_key: PublicKey) -> PeerBehaviour {
        let identify_config = IdentifyConfig::new("/substrate/1.0".to_string(), local_public_key)
            .with_agent_version(AGENT.to_string())
            // Do not cache peer info.
            .with_cache_size(0);
        let identify = Identify::new(identify_config);

        Self {
            ping: Ping::new(PingConfig::new()),
            identify,
            details: FnvHashMap::default(),
            external_addresses: HashSet::default(),
        }
    }
}

struct NodeDetails {
    /// Connected endpoints with this peer.
    pub connections: Vec<ConnectedPoint>,
    /// e.g. `ipfs/1.0.0` or `polkadot/1.0.0`.
    pub protocol_version: Option<String>,
    /// Name and version of the peer, similar to the `User-Agent` header in
    /// the HTTP protocol.
    pub agent_version: Option<String>,
    /// The list of protocols supported by the peer, e.g. `/ipfs/ping/1.0.0`.
    pub protocols: HashSet<String>,
}

impl NodeDetails {
    pub fn new(connection: ConnectedPoint) -> NodeDetails {
        const INITIAL_CAPACITY: usize = 16;

        let mut connections = Vec::with_capacity(INITIAL_CAPACITY);
        connections.push(connection);

        NodeDetails {
            connections,
            protocol_version: None,
            agent_version: None,
            protocols: HashSet::new(),
        }
    }
}

/// Peer info event emitted to swarm.
#[derive(Debug)]
pub enum PeerInfoEvent {
    /// Identified a peer.
    Identified {
        /// Id of the peer that has been identified.
        peer_id: PeerId,
        /// Information about the peer.
        info: IdentifyInfo,
    },
}

impl NetworkBehaviour for PeerBehaviour {
    type ConnectionHandler = ConnectionHandlerSelect<
        <Ping as NetworkBehaviour>::ConnectionHandler,
        <Identify as NetworkBehaviour>::ConnectionHandler,
    >;
    type ToSwarm = PeerInfoEvent;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.ping
            .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)?;
        self.identify
            .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _maybe_peer: Option<PeerId>,
        _addresses: &[Multiaddr],
        _effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        // Multiaddr is returned by other protocols.
        Ok(Vec::new())
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        let ping_handler = self.ping.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        )?;
        let identify_handler = self.identify.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        )?;
        Ok(ping_handler.select(identify_handler))
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        let ping_handler = self.ping.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
        )?;
        let identify_handler = self.identify.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
        )?;
        Ok(ping_handler.select(identify_handler))
    }

    fn on_swarm_event(&mut self, event: FromSwarm<Self::ConnectionHandler>) {
        match event {
            FromSwarm::ConnectionEstablished(
                e @ ConnectionEstablished {
                    peer_id, endpoint, ..
                },
            ) => {
                self.ping
                    .on_swarm_event(FromSwarm::ConnectionEstablished(e));
                self.identify
                    .on_swarm_event(FromSwarm::ConnectionEstablished(e));

                self.details
                    .entry(peer_id)
                    .and_modify(|details| {
                        details.connections.push(endpoint.clone());
                    })
                    .or_insert_with(|| NodeDetails::new(endpoint.clone()));
            }
            FromSwarm::ConnectionClosed(ConnectionClosed {
                peer_id,
                connection_id,
                endpoint,
                handler,
                remaining_established,
            }) => {
                let (ping_handler, identity_handler) = handler.into_inner();
                self.ping
                    .on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                        peer_id,
                        connection_id,
                        endpoint,
                        handler: ping_handler,
                        remaining_established,
                    }));
                self.identify
                    .on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                        peer_id,
                        connection_id,
                        endpoint,
                        handler: identity_handler,
                        remaining_established,
                    }));

                if let Some(node) = self.details.get_mut(&peer_id) {
                    node.connections.retain(|conn| conn != endpoint)
                }
            }
            FromSwarm::DialFailure(DialFailure {
                peer_id,
                error,
                connection_id,
            }) => {
                self.ping
                    .on_swarm_event(FromSwarm::DialFailure(DialFailure {
                        peer_id,
                        error,
                        connection_id,
                    }));
                self.identify
                    .on_swarm_event(FromSwarm::DialFailure(DialFailure {
                        peer_id,
                        error,
                        connection_id,
                    }));
            }
            FromSwarm::ListenerClosed(e) => {
                self.ping.on_swarm_event(FromSwarm::ListenerClosed(e));
                self.identify.on_swarm_event(FromSwarm::ListenerClosed(e));
            }
            FromSwarm::ListenFailure(ListenFailure {
                local_addr,
                send_back_addr,
                error,
                connection_id,
            }) => {
                self.ping
                    .on_swarm_event(FromSwarm::ListenFailure(ListenFailure {
                        local_addr,
                        send_back_addr,
                        error,
                        connection_id,
                    }));
                self.identify
                    .on_swarm_event(FromSwarm::ListenFailure(ListenFailure {
                        local_addr,
                        send_back_addr,
                        error,
                        connection_id,
                    }));
            }
            FromSwarm::ListenerError(e) => {
                self.ping.on_swarm_event(FromSwarm::ListenerError(e));
                self.identify.on_swarm_event(FromSwarm::ListenerError(e));
            }
            FromSwarm::NewListener(e) => {
                self.ping.on_swarm_event(FromSwarm::NewListener(e));
                self.identify.on_swarm_event(FromSwarm::NewListener(e));
            }
            FromSwarm::ExpiredListenAddr(e) => {
                self.ping.on_swarm_event(FromSwarm::ExpiredListenAddr(e));
                self.identify
                    .on_swarm_event(FromSwarm::ExpiredListenAddr(e));
            }
            FromSwarm::AddressChange(
                e @ AddressChange {
                    peer_id, old, new, ..
                },
            ) => {
                self.ping.on_swarm_event(FromSwarm::AddressChange(e));
                self.identify.on_swarm_event(FromSwarm::AddressChange(e));

                self.details.entry(peer_id).and_modify(|details| {
                    details
                        .connections
                        .iter_mut()
                        .find(|conn| conn == &old)
                        .map(|conn| *conn = new.clone());
                });
            }
            FromSwarm::NewListenAddr(e) => {
                self.ping.on_swarm_event(FromSwarm::NewListenAddr(e));
                self.identify.on_swarm_event(FromSwarm::NewListenAddr(e));
            }
            FromSwarm::NewExternalAddrCandidate(e) => {
                self.ping
                    .on_swarm_event(FromSwarm::NewExternalAddrCandidate(e));
                self.identify
                    .on_swarm_event(FromSwarm::NewExternalAddrCandidate(e));
            }
            FromSwarm::ExternalAddrConfirmed(e) => {
                self.ping
                    .on_swarm_event(FromSwarm::ExternalAddrConfirmed(e));
                self.identify
                    .on_swarm_event(FromSwarm::ExternalAddrConfirmed(e));

                self.external_addresses.insert(e.addr.clone());
            }
            FromSwarm::ExternalAddrExpired(e) => {
                self.external_addresses.remove(e.addr);
            }
        }
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {
            Either::Left(event) => {
                self.ping
                    .on_connection_handler_event(peer_id, connection_id, event)
            }
            Either::Right(event) => {
                self.identify
                    .on_connection_handler_event(peer_id, connection_id, event)
            }
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context,
        params: &mut impl PollParameters,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        loop {
            match self.ping.poll(cx, params) {
                Poll::Pending => break,
                Poll::Ready(ToSwarm::GenerateEvent(ev)) => {
                    log::debug!(
                        "PingEvent peer_id={:?} connection_id={:?} result {:?}",
                        ev.peer,
                        ev.connection,
                        ev.result
                    );
                }
                Poll::Ready(ToSwarm::Dial { opts }) => return Poll::Ready(ToSwarm::Dial { opts }),
                Poll::Ready(ToSwarm::NotifyHandler {
                    peer_id,
                    handler,
                    event,
                }) => {
                    return Poll::Ready(ToSwarm::NotifyHandler {
                        peer_id,
                        handler,
                        event: Either::Left(event),
                    })
                }
                Poll::Ready(ToSwarm::CloseConnection {
                    peer_id,
                    connection,
                }) => {
                    return Poll::Ready(ToSwarm::CloseConnection {
                        peer_id,
                        connection,
                    })
                }
                Poll::Ready(ToSwarm::ListenOn { opts }) => {
                    return Poll::Ready(ToSwarm::ListenOn { opts })
                }
                Poll::Ready(ToSwarm::RemoveListener { id }) => {
                    return Poll::Ready(ToSwarm::RemoveListener { id })
                }
                Poll::Ready(ToSwarm::ExternalAddrExpired(address)) => {
                    return Poll::Ready(ToSwarm::ExternalAddrExpired(address))
                }
                Poll::Ready(ToSwarm::ExternalAddrConfirmed(address)) => {
                    return Poll::Ready(ToSwarm::ExternalAddrConfirmed(address))
                }
                Poll::Ready(ToSwarm::NewExternalAddrCandidate(address)) => {
                    return Poll::Ready(ToSwarm::NewExternalAddrCandidate(address))
                }
            }
        }

        loop {
            match self.identify.poll(cx, params) {
                Poll::Pending => break,
                Poll::Ready(ToSwarm::GenerateEvent(event)) => match event {
                    IdentifyEvent::Received { peer_id, info, .. } => {
                        self.details.entry(peer_id).and_modify(|details| {
                            details.agent_version = Some(info.agent_version.clone());
                            details.protocol_version = Some(info.protocol_version.clone());
                            details.protocols = info
                                .protocols
                                .iter()
                                .map(|proto| proto.to_string())
                                .collect();
                        });

                        let event = PeerInfoEvent::Identified { peer_id, info };
                        return Poll::Ready(ToSwarm::GenerateEvent(event));
                    }
                    IdentifyEvent::Error { peer_id, error } => {
                        log::debug!("Identification with peer={:?} error={}", peer_id, error)
                    }
                    IdentifyEvent::Pushed { .. } => {}
                    IdentifyEvent::Sent { .. } => {}
                },
                Poll::Ready(ToSwarm::Dial { opts }) => return Poll::Ready(ToSwarm::Dial { opts }),
                Poll::Ready(ToSwarm::NotifyHandler {
                    peer_id,
                    handler,
                    event,
                }) => {
                    return Poll::Ready(ToSwarm::NotifyHandler {
                        peer_id,
                        handler,
                        event: Either::Right(event),
                    })
                }
                Poll::Ready(ToSwarm::ListenOn { opts }) => {
                    return Poll::Ready(ToSwarm::ListenOn { opts })
                }
                Poll::Ready(ToSwarm::RemoveListener { id }) => {
                    return Poll::Ready(ToSwarm::RemoveListener { id })
                }
                Poll::Ready(ToSwarm::ExternalAddrExpired(address)) => {
                    return Poll::Ready(ToSwarm::ExternalAddrExpired(address))
                }
                Poll::Ready(ToSwarm::ExternalAddrConfirmed(address)) => {
                    return Poll::Ready(ToSwarm::ExternalAddrConfirmed(address))
                }
                Poll::Ready(ToSwarm::NewExternalAddrCandidate(address)) => {
                    return Poll::Ready(ToSwarm::NewExternalAddrCandidate(address))
                }
                Poll::Ready(ToSwarm::CloseConnection {
                    peer_id,
                    connection,
                }) => {
                    return Poll::Ready(ToSwarm::CloseConnection {
                        peer_id,
                        connection,
                    })
                }
            }
        }

        Poll::Pending
    }
}
