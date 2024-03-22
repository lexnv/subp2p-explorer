// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use libp2p::swarm::NetworkBehaviour;

pub mod discovery;
pub mod notifications;
pub mod peer_behavior;
pub mod transport;
pub mod util;

/// Network behavior for subtrate based chains.
#[derive(NetworkBehaviour)]
pub struct Behaviour {
    /// Notification protocols.
    pub notifications: notifications::behavior::Notifications,
    /// Implements Ping and Identity and stores peer information in a cache.
    pub peer_info: peer_behavior::PeerBehaviour,
    /// Discovers nodes of the network.
    pub discovery: discovery::Discovery,
}

/// Protocol index for block-announces.
pub const BLOCK_ANNOUNCES_INDEX: usize = 0;
/// Protocol index for transactions.
pub const TRANSACTIONS_INDEX: usize = 1;
