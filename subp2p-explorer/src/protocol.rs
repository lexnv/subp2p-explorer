// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use std::{
    collections::HashMap,
    hash::Hash,
    sync::{atomic::AtomicUsize, Arc},
};

// let (s, r) = async_channel::unbounded();

use libp2p::{identity::ed25519::Keypair, PeerId};

/// The role of the connected peer in the network.
pub enum ProtocolRole {
    /// Full node that stores the state of the chain. (ie substrate binary).
    ///
    /// Does not participate in consensus.
    FullNode,
    /// Light node to advance decentralization. (ie smoldiot).
    ///
    /// Does not participate in consensus.
    LightNode,
    /// Authors blocks and participates in the consensus.
    Authority,
}

impl ProtocolRole {
    /// Returns the scale-encoded representation of this enum.
    pub fn encoded(&self) -> u8 {
        match self {
            ProtocolRole::FullNode => 0b_0000_0001,
            ProtocolRole::LightNode => 0b_0000_0010,
            ProtocolRole::Authority => 0b_0000_0100,
        }
    }
}

/// The name of the notifcation protocol.
pub type ProtocolName = String;

/// The index (id) of the notifcation protocol.
pub type ProtocolIndex = usize;

/// The configuration of a notification protocol.
pub struct NotificationProtocolConfig {
    /// The name of the protocol. (ie `/transactions/1`)
    pub name: String,
}

// Substrate network service. Handles network IO and manages connectivity.
// pub struct NetworkService<B: BlockT + 'static, H: ExHashT> {

/// Contains all connections and logic for the substrate p2p networks.
pub struct Network {
    /// List of supported notification protocols over the network.
    notification_protocols: Vec<String>,
    /// Generate substream IDs.
    substream_id_generator: usize,

    /// Number of peers we're connected to.
    num_connected: Arc<AtomicUsize>,
    /// Local copy of the `PeerId` of the local node.
    local_peer_id: PeerId,
    /// The `KeyPair` that defines the `PeerId` of the local node.
    local_identity: Keypair,

    /// Protocol name to index mapping for notification protocols.
    notification_protocol_to_index: HashMap<ProtocolName, ProtocolIndex>,
}

impl Network {
    /// Get the next substream ID.
    fn next_substream_id(&mut self) -> usize {
        let current = self.substream_id_generator;
        self.substream_id_generator += 1;
        current
    }

    pub fn new() -> Network {}
}

enum PeerDirection {
    Inbound,
    Outbound,
}

pub struct ProtocolController {
    /// The index of the protocol.
    index: ProtocolIndex,

    /// Connected peers with associated direction.
    peers: HashMap<PeerId, PeerDirection>,
}

impl ProtocolController {
    pub fn new(index: ProtocolIndex) -> ProtocolController {
        ProtocolController {
            index,
            peers: HashMap::new(),
        }
    }

    /// Runs the controller.
    pub async fn run(mut self) {
        while self.handle_tasks() {}
    }

    /// Returns false if the controller should stop.
    pub async fn handle_tasks(&mut self) -> bool {}
}
