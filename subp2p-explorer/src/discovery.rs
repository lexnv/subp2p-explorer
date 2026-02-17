// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use std::time::Duration;

use libp2p::{
    kad::{self, store::MemoryStore},
    PeerId, StreamProtocol,
};

/// Discovery protocol of the p2p network.
///
/// The main discovery protocol used by substrate chains is Kademlia.
pub type Discovery = kad::Behaviour<MemoryStore>;

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

impl Default for DiscoveryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoveryBuilder {
    /// Create a new [`DiscoveryBuilder`].
    pub fn new() -> DiscoveryBuilder {
        DiscoveryBuilder {
            max_packet_size: 16 * 1024 * 1024,
            record_ttl: None,
            provider_ttl: None,
            query_timeout: Duration::from_secs(15),
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
    /// Default: 15 seconds.
    pub fn query_timeout(mut self, query_timeout: Duration) -> Self {
        self.query_timeout = query_timeout;
        self
    }

    /// Build the discovery protocol.
    pub fn build(self, local_peer_id: PeerId, genesis_hash: &str) -> Discovery {
        let kademlia_protocol =
            StreamProtocol::try_from_owned(format!("/{genesis_hash}/kad"))
                .expect("Protocol name starts with '/'; qed");

        let mut config = kad::Config::new(kademlia_protocol);
        config.set_max_packet_size(self.max_packet_size);
        config.set_record_ttl(self.record_ttl);
        config.set_provider_record_ttl(self.provider_ttl);
        config.set_query_timeout(self.query_timeout);

        // Use memory store for kad.
        let store = MemoryStore::new(local_peer_id);
        kad::Behaviour::with_config(local_peer_id, store, config)
    }
}
