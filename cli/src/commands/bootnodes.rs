// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use crate::utils::dial_error_message;
use futures::StreamExt;
use libp2p::{
    identify::{self},
    identity,
    swarm::{dial_opts::DialOpts, ConnectionId, SwarmEvent},
    Multiaddr, PeerId, Swarm,
};

use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::time::Duration;
use subp2p_explorer::peer_behavior::AGENT;

/// Outcome of probing a single bootnode address.
enum AddressOutcome {
    /// The peer responded to identify over a connection on this address.
    Identified,
    /// The address could not be verified.
    Failed(String),
}

/// A dial in flight probing one bootnode address.
struct ActiveDial {
    /// The peer the address belongs to.
    peer: PeerId,
    /// The address being probed.
    address: Multiaddr,
    /// Set once the peer answered identify on this connection.
    identified: bool,
}

/// Holds the state machine needed to check if the provided
/// list of peers is reachable and responds to the identify
/// protocol.
struct Bootnodes {
    /// The bootnodes to validate.
    bootnodes: HashMap<PeerId, Vec<Multiaddr>>,
    /// Genesis hash.
    genesis: Option<String>,
    /// Outcome of every probed address. An address missing from this map was
    /// still being probed when the timeout hit.
    outcomes: HashMap<Multiaddr, AddressOutcome>,
    /// Addresses waiting to be dialed, per peer. At most one dial per peer is
    /// in flight: substrate nodes keep a single connection per peer and close
    /// any redundant one, which would make a working address look unreachable.
    queued_dials: HashMap<PeerId, VecDeque<Multiaddr>>,
    /// Dials in flight (or still connected), keyed by connection id.
    active_dials: HashMap<ConnectionId, ActiveDial>,
    /// The identify data collected for peers.
    identify_data: HashMap<PeerId, identify::Info>,
}

impl Bootnodes {
    /// Construct a new [`Bootnodes`] with the provided bootnodes.
    pub fn new(bootnodes: HashMap<PeerId, Vec<Multiaddr>>, genesis: Option<String>) -> Self {
        let queued_dials = bootnodes
            .iter()
            .map(|(peer, addrs)| (*peer, addrs.iter().cloned().collect()))
            .collect();

        Self {
            bootnodes,
            genesis,
            outcomes: Default::default(),
            queued_dials,
            active_dials: Default::default(),
            identify_data: Default::default(),
        }
    }

    async fn build_swarm() -> Swarm<identify::Behaviour> {
        let local_key = identity::Keypair::generate_ed25519();

        let behavior = identify::Behaviour::new(
            identify::Config::new("/substrate/1.0".to_string(), local_key.public())
                .with_agent_version(AGENT.to_string())
                // Do not cache peer info.
                .with_cache_size(0),
        );

        let tcp_config = libp2p::tcp::Config::new().nodelay(true);

        libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp_config,
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .expect("Can construct TCP; qed")
            .with_dns()
            .expect("Can construct DNS; qed")
            .with_websocket(libp2p::noise::Config::new, libp2p::yamux::Config::default)
            .await
            .expect("Can construct WebSocket; qed")
            .with_behaviour(|_key| behavior)
            .expect("Can construct behaviour; qed")
            .build()
    }

    /// Every address of every bootnode has an outcome.
    fn all_resolved(&self) -> bool {
        self.bootnodes
            .values()
            .flatten()
            .all(|addr| self.outcomes.contains_key(addr))
    }

    /// Probe the next queued address of `peer`.
    ///
    /// A dial that cannot even start is recorded as failed instead of
    /// aborting the verification of the remaining addresses.
    fn advance_peer_dial(&mut self, swarm: &mut Swarm<identify::Behaviour>, peer: PeerId) {
        if self.active_dials.values().any(|dial| dial.peer == peer) {
            return;
        }

        while let Some(addr) = self
            .queued_dials
            .get_mut(&peer)
            .and_then(|queue| queue.pop_front())
        {
            let opts = DialOpts::unknown_peer_id().address(addr.clone()).build();
            let connection_id = opts.connection_id();

            match swarm.dial(opts) {
                Ok(()) => {
                    println!("Dialing {addr}");
                    self.active_dials.insert(
                        connection_id,
                        ActiveDial {
                            peer,
                            address: addr,
                            identified: false,
                        },
                    );
                    return;
                }
                Err(e) => {
                    self.outcomes
                        .insert(addr, AddressOutcome::Failed(dial_error_message(&e)));
                }
            }
        }

        self.queued_dials.remove(&peer);
    }

    /// Dial the provided bootnodes and capture the `identify::Info` details of each peer.
    ///
    /// Addresses of the same peer are probed one at a time so that the single
    /// connection substrate nodes keep per peer never invalidates a working
    /// address.
    pub async fn verify_bootnodes(&mut self) -> Result<(), Box<dyn Error>> {
        let mut swarm = Self::build_swarm().await;

        let peers: Vec<PeerId> = self.queued_dials.keys().copied().collect();
        for peer in peers {
            self.advance_peer_dial(&mut swarm, peer);
        }

        while !self.all_resolved() {
            match swarm.select_next_some().await {
                SwarmEvent::Behaviour(event) => match event {
                    identify::Event::Received {
                        peer_id,
                        info,
                        connection_id,
                    } => {
                        // Store the info data to ensure that we validate the protocols supported by the remote peer.
                        self.identify_data.insert(peer_id, info);

                        if let Some(dial) = self.active_dials.get_mut(&connection_id) {
                            let outcome = if peer_id == dial.peer {
                                dial.identified = true;
                                AddressOutcome::Identified
                            } else {
                                AddressOutcome::Failed(format!("wrong peer ID: {peer_id}"))
                            };
                            self.outcomes.insert(dial.address.clone(), outcome);

                            // Free the single connection slot the remote keeps
                            // for us before probing its next address.
                            let has_more = self
                                .queued_dials
                                .get(&dial.peer)
                                .is_some_and(|queue| !queue.is_empty());
                            if has_more {
                                let _ = swarm.disconnect_peer_id(peer_id);
                            }
                        }
                    }
                    identify::Event::Sent { peer_id, .. } => {
                        println!("Sent identify info to {peer_id:?}");
                    }
                    identify::Event::Pushed { peer_id, .. } => {
                        println!("Pushed identify info to {peer_id:?}");
                    }
                    identify::Event::Error { peer_id, error, .. } => {
                        println!("Error sending identify info to {peer_id:?}: {error:?}");
                    }
                },
                SwarmEvent::OutgoingConnectionError {
                    connection_id,
                    error,
                    ..
                } => {
                    if let Some(dial) = self.active_dials.remove(&connection_id) {
                        self.outcomes
                            .entry(dial.address)
                            .or_insert_with(|| AddressOutcome::Failed(dial_error_message(&error)));
                        self.advance_peer_dial(&mut swarm, dial.peer);
                    }
                }
                SwarmEvent::ConnectionClosed { connection_id, .. } => {
                    if let Some(dial) = self.active_dials.remove(&connection_id) {
                        if !dial.identified {
                            self.outcomes.entry(dial.address).or_insert_with(|| {
                                AddressOutcome::Failed(
                                    "connection closed before identify response".into(),
                                )
                            });
                        }
                        self.advance_peer_dial(&mut swarm, dial.peer);
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// The protocols reported by the peer are derived from the genesis hash,
    /// when a genesis hash is provided.
    fn peer_protocols_match(&self, peer: &PeerId) -> bool {
        self.identify_data
            .get(peer)
            .map(|info| {
                self.genesis
                    .as_ref()
                    .map(|genesis| {
                        info.protocols
                            .iter()
                            .any(|proto| proto.as_ref().contains(genesis))
                    })
                    .unwrap_or(true)
            })
            .unwrap_or(false)
    }

    /// An address is valid when:
    /// - the peer behind it responded to the identify protocol over a
    ///   connection on this specific address
    /// - the p2p protocols are derived from the genesis hash (when the genesis hash is provided).
    ///
    /// Returns the reason the address is invalid otherwise.
    pub fn address_outcome(&self, peer: &PeerId, addr: &Multiaddr) -> Result<(), String> {
        match self.outcomes.get(addr) {
            Some(AddressOutcome::Identified) => {
                if self.peer_protocols_match(peer) {
                    Ok(())
                } else {
                    Err("p2p protocols do not match the genesis hash".into())
                }
            }
            Some(AddressOutcome::Failed(reason)) => Err(reason.clone()),
            None => Err("no response before the timeout".into()),
        }
    }
}

pub async fn verify_bootnodes(
    bootnodes: Vec<String>,
    genesis: Option<String>,
) -> Result<(), Box<dyn Error>> {
    // Parse the provided bootnodes as `PeerId` and `MultiAddress`.
    let mut nodes: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();

    for bootnode in bootnodes {
        let parts: Vec<_> = bootnode.split('/').collect();
        let peer = parts.last().expect("Valid bootnode has peer; qed");
        let multiaddress: Multiaddr = bootnode.parse().expect("Valid multiaddress; qed");
        let peer_id: PeerId = peer.parse().expect("Valid peer ID; qed");

        let addresses = nodes.entry(peer_id).or_default();
        if !addresses.contains(&multiaddress) {
            addresses.push(multiaddress);
        }
    }

    let mut state = Bootnodes::new(nodes.clone(), genesis);
    let _ = tokio::time::timeout(Duration::from_secs(25), state.verify_bootnodes()).await;
    println!();

    let mut valid_addresses = Vec::new();
    let mut invalid_addresses = Vec::new();
    for (peer, addresses) in &nodes {
        for addr in addresses {
            match state.address_outcome(peer, addr) {
                Ok(()) => valid_addresses.push(addr),
                Err(reason) => invalid_addresses.push((addr, reason)),
            }
        }
    }

    if !valid_addresses.is_empty() {
        println!("Valid bootnodes:");
        for addr in valid_addresses {
            println!(" {addr}");
        }
        println!();
    }

    if !invalid_addresses.is_empty() {
        println!("Invalid bootnodes:");
        for (addr, reason) in invalid_addresses {
            println!(" {addr} — {reason}");
        }
        println!();
    }

    Ok(())
}
