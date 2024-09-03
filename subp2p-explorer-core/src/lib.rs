pub mod types;

use async_trait::async_trait;
use std::collections::HashSet;
use types::{multiaddr::Multiaddr, peer_id::PeerId};

pub mod libp2p;
pub mod litep2p;

/// Type representing a query ID.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct QueryId(usize);

/// The event produced by the network backend.
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

/// The main trait for the network backend.
///
/// This trait exposes the necessary methods to interact with the network backend.
#[async_trait]
pub trait NetworkBackend {
    /// Get the next event from the network backend.
    ///
    /// This method must be polled to advance the state of the network backend.
    /// It returns `None` if there are no more events to process, in which case the caller should
    /// stop the polling process.
    ///
    /// Further, this method can be used as a form of backpressure to limit the number of events
    /// that are processed by the network backend.
    fn poll_next_event(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context,
    ) -> std::task::Poll<Option<NetworkEvent>> {
        std::task::Poll::Pending
    }

    /// Find a node in the network.
    async fn find_node(&mut self, peer: PeerId) -> QueryId;

    /// Add a known peer to the network.
    ///
    /// This should be called with the bootnodes of the network before starting the discovery process.
    async fn add_known_peer(&mut self, peer_id: PeerId, address: Vec<Multiaddr>);

    /// Get the listen addresses of the network backend.
    async fn listen_addresses(&mut self) -> Vec<Multiaddr>;
}
