// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use crate::utils::dial_error_message;
use futures::StreamExt;
use libp2p::{
    identify, identity,
    multiaddr::Protocol,
    swarm::{dial_opts::DialOpts, ConnectionId, SwarmEvent},
    Multiaddr, PeerId, Swarm,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::time::Duration;
use subp2p_explorer::peer_behavior::AGENT;

async fn build_swarm() -> Swarm<identify::Behaviour> {
    let local_key = identity::Keypair::generate_ed25519();

    let behavior = identify::Behaviour::new(
        identify::Config::new("/substrate/1.0".to_string(), local_key.public())
            .with_agent_version(AGENT.to_string())
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

/// The peer ID named by the `/p2p/` component of the address, if any.
fn peer_id_of(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|proto| match proto {
        Protocol::P2p(peer) => Some(peer),
        _ => None,
    })
}

/// Outcome of probing a single address.
enum AddressOutcome {
    /// The peer answered identify for this address.
    Identified(PeerId),
    /// A connection was established on this address, but no identify response
    /// arrived (yet).
    Connected(PeerId),
    /// The address could not be verified.
    Failed(String),
}

/// A dial in flight (or still connected), probing one address.
struct ActiveDial {
    /// The address being probed.
    address: Multiaddr,
    /// Peer ID from the `/p2p/` component. Addresses naming the same peer are
    /// probed one at a time.
    group: Option<PeerId>,
    /// Set once the peer answered identify on this connection.
    identified: bool,
}

struct DialProbe {
    swarm: Swarm<identify::Behaviour>,
    /// The addresses to probe, in input order.
    addresses: Vec<Multiaddr>,
    /// Outcome of every probed address, strongest evidence kept.
    outcomes: HashMap<Multiaddr, AddressOutcome>,
    /// Addresses waiting to be dialed, per peer named in the address. At most
    /// one dial per peer is in flight: substrate nodes keep a single
    /// connection per peer and close any redundant one, which would make a
    /// working address look unreachable.
    queued_dials: HashMap<PeerId, VecDeque<Multiaddr>>,
    /// Dials in flight (or still connected), keyed by connection id.
    active_dials: HashMap<ConnectionId, ActiveDial>,
    /// Peers that answered identify on any connection, used to attribute the
    /// response to a redundant connection the remote closed.
    identified_peers: HashSet<PeerId>,
}

impl DialProbe {
    fn new(swarm: Swarm<identify::Behaviour>, addresses: Vec<Multiaddr>) -> Self {
        Self {
            swarm,
            addresses,
            outcomes: HashMap::new(),
            queued_dials: HashMap::new(),
            active_dials: HashMap::new(),
            identified_peers: HashSet::new(),
        }
    }

    /// Record the outcome of probing `addr`, never downgrading the evidence
    /// already gathered for it.
    fn record_outcome(&mut self, addr: Multiaddr, outcome: AddressOutcome) {
        match (self.outcomes.get(&addr), &outcome) {
            (Some(AddressOutcome::Identified(_)), _) => (),
            (Some(AddressOutcome::Connected(_)), AddressOutcome::Failed(_)) => (),
            _ => {
                self.outcomes.insert(addr, outcome);
            }
        }
    }

    /// Every address either answered identify or failed. Addresses that are
    /// merely connected keep the probe running: identify may still answer.
    fn all_resolved(&self) -> bool {
        self.addresses.iter().all(|addr| {
            matches!(
                self.outcomes.get(addr),
                Some(AddressOutcome::Identified(_)) | Some(AddressOutcome::Failed(_))
            )
        })
    }

    /// Dial `addr`, recording a failure instead of aborting the probe when
    /// the dial cannot even start.
    fn dial(&mut self, addr: Multiaddr, group: Option<PeerId>) -> bool {
        let opts = DialOpts::unknown_peer_id().address(addr.clone()).build();
        let connection_id = opts.connection_id();

        match self.swarm.dial(opts) {
            Ok(()) => {
                println!("Dialing {addr}");
                self.active_dials.insert(
                    connection_id,
                    ActiveDial {
                        address: addr,
                        group,
                        identified: false,
                    },
                );
                true
            }
            Err(e) => {
                self.record_outcome(addr, AddressOutcome::Failed(dial_error_message(&e)));
                false
            }
        }
    }

    /// Probe the next queued address of `peer`.
    fn advance_peer_dial(&mut self, peer: PeerId) {
        if self
            .active_dials
            .values()
            .any(|dial| dial.group == Some(peer))
        {
            return;
        }

        while let Some(addr) = self
            .queued_dials
            .get_mut(&peer)
            .and_then(|queue| queue.pop_front())
        {
            if self.dial(addr, Some(peer)) {
                return;
            }
        }

        self.queued_dials.remove(&peer);
    }

    /// Queue every address and start the probes.
    fn start(&mut self) {
        for addr in self.addresses.clone() {
            match peer_id_of(&addr) {
                Some(peer) => {
                    self.queued_dials.entry(peer).or_default().push_back(addr);
                }
                // Without a `/p2p/` component the peer is unknown until the
                // connection is established; probe right away.
                None => {
                    self.dial(addr, None);
                }
            }
        }

        let peers: Vec<PeerId> = self.queued_dials.keys().copied().collect();
        for peer in peers {
            self.advance_peer_dial(peer);
        }
    }

    async fn drive(&mut self) {
        while !self.all_resolved() {
            let event = self.swarm.select_next_some().await;
            self.handle_event(event);
        }
    }

    fn handle_event(&mut self, event: SwarmEvent<identify::Event>) {
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                ..
            } => {
                if let Some(dial) = self.active_dials.get(&connection_id) {
                    let addr = dial.address.clone();
                    self.record_outcome(addr, AddressOutcome::Connected(peer_id));
                }
            }

            SwarmEvent::Behaviour(event) => match event {
                identify::Event::Received {
                    peer_id,
                    info,
                    connection_id,
                } => {
                    println!();
                    println!("Peer: {peer_id}");
                    println!("  Agent Version:    {}", info.agent_version);
                    println!("  Protocol Version: {}", info.protocol_version);
                    println!("  Listen Addresses:");
                    for addr in &info.listen_addrs {
                        println!("    {addr}");
                    }
                    println!("  Observed Address: {}", info.observed_addr);
                    println!("  Protocols:");
                    for proto in &info.protocols {
                        println!("    {proto}");
                    }

                    self.identified_peers.insert(peer_id);

                    let attributed = match self.active_dials.get_mut(&connection_id) {
                        Some(dial) => {
                            dial.identified = true;
                            Some((dial.address.clone(), dial.group))
                        }
                        None => None,
                    };
                    if let Some((addr, group)) = attributed {
                        self.record_outcome(addr, AddressOutcome::Identified(peer_id));

                        // Free the single connection slot the remote keeps for
                        // us before probing its next address.
                        let has_more = group.is_some_and(|group| {
                            self.queued_dials
                                .get(&group)
                                .is_some_and(|queue| !queue.is_empty())
                        });
                        if has_more {
                            let _ = self.swarm.disconnect_peer_id(peer_id);
                        }
                    }
                }
                identify::Event::Error { peer_id, error, .. } => {
                    println!();
                    println!("Error identifying {peer_id}: {error}");
                }
                _ => {}
            },

            SwarmEvent::OutgoingConnectionError {
                connection_id,
                error,
                ..
            } => {
                if let Some(dial) = self.active_dials.remove(&connection_id) {
                    self.record_outcome(
                        dial.address,
                        AddressOutcome::Failed(dial_error_message(&error)),
                    );
                    if let Some(group) = dial.group {
                        self.advance_peer_dial(group);
                    }
                }
            }

            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                ..
            } => {
                if let Some(dial) = self.active_dials.remove(&connection_id) {
                    if !dial.identified {
                        if self.identified_peers.contains(&peer_id) {
                            // A redundant connection the remote closed: the
                            // identify response gathered on the peer's other
                            // connection vouches for this address too.
                            self.record_outcome(dial.address, AddressOutcome::Identified(peer_id));
                        } else {
                            // The connection is gone; identify can no longer
                            // answer on this address.
                            self.outcomes.insert(
                                dial.address,
                                AddressOutcome::Failed(
                                    "connection closed before identify response".into(),
                                ),
                            );
                        }
                    }
                    if let Some(group) = dial.group {
                        self.advance_peer_dial(group);
                    }
                }
            }

            _ => {}
        }
    }
}

pub async fn dial_peer(addresses: Vec<String>, timeout: Duration) -> Result<(), Box<dyn Error>> {
    let mut parsed: Vec<Multiaddr> = Vec::new();
    for addr in &addresses {
        let multiaddr: Multiaddr = addr.parse()?;
        if !parsed.contains(&multiaddr) {
            parsed.push(multiaddr);
        }
    }

    let swarm = build_swarm().await;
    let mut probe = DialProbe::new(swarm, parsed);
    probe.start();

    let timed_out = tokio::time::timeout(timeout, probe.drive()).await.is_err();

    let identified = probe
        .addresses
        .iter()
        .filter(|addr| {
            matches!(
                probe.outcomes.get(addr),
                Some(AddressOutcome::Identified(_))
            )
        })
        .count();

    println!();
    if timed_out {
        println!("Timeout after {}s.", timeout.as_secs());
    }
    println!(
        "Received identify from {identified}/{} address(es):",
        probe.addresses.len()
    );
    for addr in &probe.addresses {
        match probe.outcomes.get(addr) {
            Some(AddressOutcome::Identified(peer)) => {
                println!("  ok      {addr} — identified peer {peer}")
            }
            Some(AddressOutcome::Connected(peer)) => println!(
                "  partial {addr} — connected to {peer}, no identify response before the timeout"
            ),
            Some(AddressOutcome::Failed(reason)) => println!("  failed  {addr} — {reason}"),
            None => println!("  failed  {addr} — no connection before the timeout"),
        }
    }

    Ok(())
}
