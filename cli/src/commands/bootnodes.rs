// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use futures::StreamExt;
use libp2p::{
    identify::{self},
    identity,
    swarm::{SwarmBuilder, SwarmEvent},
    Multiaddr, PeerId, Swarm,
};

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::time::Duration;
use subp2p_explorer::{peer_behavior::AGENT, transport::TransportBuilder};

/// Holds the state machine needed to check if the provided
/// list of peers is reachable and responds to the identify
/// protocol.
struct Bootnodes {
    /// The bootnodes to validate.
    bootnodes: HashMap<PeerId, Vec<Multiaddr>>,
    /// Genesis hash.
    genesis: Option<String>,
    /// The list of bootnodes that did not respond yet to the `identify` protocol.
    pending_peer_responses: HashSet<PeerId>,
    /// The identify data collected for peers.
    ///
    /// This is guaranteed to contain entries for all `bootnodes.keys()`, or a subset
    /// of those if `identifies` remains non empty after the query timeout.
    identify_data: HashMap<PeerId, identify::Info>,
}

impl Bootnodes {
    /// Construct a new [`BootnodesStateMachine`] with the provided bootnodes.
    pub fn new(bootnodes: HashMap<PeerId, Vec<Multiaddr>>, genesis: Option<String>) -> Self {
        let pending_peer_responses = bootnodes.keys().cloned().collect();

        Self {
            bootnodes,
            genesis,
            pending_peer_responses,
            identify_data: Default::default(),
        }
    }

    fn build_swarm() -> Swarm<identify::Behaviour> {
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());

        let transport = TransportBuilder::new().build(local_key.clone());
        let behavior = identify::Behaviour::new(
            identify::Config::new("/substrate/1.0".to_string(), local_key.public())
                .with_agent_version(AGENT.to_string())
                // Do not cache peer info.
                .with_cache_size(0),
        );

        SwarmBuilder::with_tokio_executor(transport, behavior, local_peer_id).build()
    }

    /// Dial the provided bootnodes and capture the `idenitify::Info` details of each peer.
    pub async fn verify_bootnodes(&mut self) -> Result<(), Box<dyn Error>> {
        let mut swarm = Self::build_swarm();

        for remotes in self.bootnodes.values() {
            for remote in remotes {
                swarm.dial(remote.clone())?;
                println!("Dialed {remote}")
            }
        }

        while !self.pending_peer_responses.is_empty() {
            if let SwarmEvent::Behaviour(event) = swarm.select_next_some().await {
                match event {
                    identify::Event::Received { peer_id, info } => {
                        println!("Received identify info from {peer_id:?}: {info:?}");

                        // Store the info data to ensure that we validate the protocols supported by the remote peer.
                        self.identify_data.insert(peer_id, info);

                        // Peer has responded to identify at least once.
                        self.pending_peer_responses.remove(&peer_id);
                    }
                    identify::Event::Sent { peer_id } => {
                        println!("Sent identify info to {peer_id:?}");
                    }
                    identify::Event::Pushed { peer_id } => {
                        println!("Pushed identify info to {peer_id:?}");
                    }
                    identify::Event::Error { peer_id, error } => {
                        println!("Error sending identify info to {peer_id:?}: {error:?}");
                    }
                }
            }
        }

        Ok(())
    }

    /// A peer is valid when:
    /// - it has responded to the identify protocol
    /// - the p2p protocols are derived from the genesis hash (when the genesis hash is provided).
    pub fn is_peer_valid(&self, peer: &PeerId) -> bool {
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
}

pub async fn verify_bootnodes(
    bootnodes: Vec<String>,
    genesis: Option<String>,
) -> Result<(), Box<dyn Error>> {
    // Parse the provided bootnodes as `PeerId` and `MultiAddress`.
    let mut nodes = HashMap::new();

    for bootnode in bootnodes {
        let parts: Vec<_> = bootnode.split('/').collect();
        let peer = parts.last().expect("Valid bootnode has peer; qed");
        let multiaddress: Multiaddr = bootnode.parse().expect("Valid multiaddress; qed");
        let peer_id: PeerId = peer.parse().expect("Valid peer ID; qed");

        println!("Bootnode peer={:?}", peer_id);
        nodes
            .entry(peer_id)
            .or_insert_with(Vec::new)
            .push(multiaddress);
    }

    let mut state = Bootnodes::new(nodes.clone(), genesis);

    let _ = tokio::time::timeout(Duration::from_secs(25), state.verify_bootnodes()).await;

    let valid_bootnodes: Vec<_> = nodes
        .iter()
        .filter(|(peer, _)| state.is_peer_valid(peer))
        .collect();
    let invalid_bootnodes: Vec<_> = nodes
        .iter()
        .filter(|(peer, _)| !state.is_peer_valid(peer))
        .collect();

    if !valid_bootnodes.is_empty() {
        println!("Valid bootnodes:");
        for (_, multiaddr) in valid_bootnodes {
            for addr in multiaddr {
                println!(" {addr}");
            }
        }
        println!()
    }

    if !invalid_bootnodes.is_empty() {
        println!("Invalid bootnodes:");
        for (_, multiaddr) in invalid_bootnodes {
            for addr in multiaddr {
                println!(" {addr}");
            }
        }
        println!()
    }

    Ok(())
}
