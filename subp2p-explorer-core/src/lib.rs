pub mod types;

use std::collections::HashSet;

use types::{multiaddr::Multiaddr, peer_id::PeerId};

pub mod libp2p;
pub mod litep2p;

pub struct NetworkBackend {}

pub enum DhtEvent {}

/// Type representing a query ID.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct QueryId(usize);

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
