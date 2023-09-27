// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use std::time::Duration;

use libp2p::{
    kad::{store::MemoryStore, Kademlia, KademliaConfig},
    PeerId, StreamProtocol,
};

/// Discovery protocol of the p2p network.
///
/// The main discovery protocol used by substrate chains is Kademlia.
pub type Discovery = Kademlia<MemoryStore>;

/// Builder for the discovery protocol (Kademlia).
pub struct DiscoveryBuilder {
    /// Modifies the maximum allowed size of individual Kademlia packets.
    max_packet_size: usize,
    /// Sets the TTL for stored records.
    record_ttl: Option<Duration>,
    /// Sets the TTL for provider records.
    provider_ttl: Option<Duration>,
    /// Sets the timeout for a single query.
    query_timeout: Duration,
}

impl DiscoveryBuilder {
    /// Create a new [`DiscoveryBuilder`].
    pub fn new() -> DiscoveryBuilder {
        DiscoveryBuilder {
            max_packet_size: 8192,
            record_ttl: None,
            provider_ttl: None,
            query_timeout: Duration::from_secs(60),
        }
    }

    /// Modifies the maximum allowed size of individual Kademlia packets.
    ///
    /// Default: 8192.
    pub fn max_packet_size(mut self, max_packet_size: usize) -> Self {
        self.max_packet_size = max_packet_size;
        self
    }

    /// Sets the TTL for stored records.
    pub fn record_ttl(mut self, record_ttl: Option<Duration>) -> Self {
        self.record_ttl = record_ttl;
        self
    }

    /// Sets the TTL for provider records.
    pub fn provider_ttl(mut self, provider_ttl: Option<Duration>) -> Self {
        self.provider_ttl = provider_ttl;
        self
    }

    /// Sets the timeout for a single query.
    ///
    /// Default: 60 seconds.
    pub fn query_timeout(mut self, query_timeout: Duration) -> Self {
        self.query_timeout = query_timeout;
        self
    }

    /// Build the discovery protocol.
    pub fn build(self, local_peer_id: PeerId, genesis_hash: &str) -> Discovery {
        let mut config = KademliaConfig::default();
        config.set_max_packet_size(self.max_packet_size);
        config.set_record_ttl(self.record_ttl);
        config.set_provider_record_ttl(self.provider_ttl);
        config.set_query_timeout(self.query_timeout);

        // Support only the genesis protocol for kademlia.
        let kademlia_protocols =
            vec![
                StreamProtocol::try_from_owned(format!("/{genesis_hash}/kad"))
                    .expect("Protocol name starts with '/'; qed"),
            ];
        config.set_protocol_names(kademlia_protocols.into_iter().map(Into::into).collect());

        // Use memory store for kad.
        let store = MemoryStore::new(local_peer_id);
        Kademlia::with_config(local_peer_id, store, config)
    }
}
