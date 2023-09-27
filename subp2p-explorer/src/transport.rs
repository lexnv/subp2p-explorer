//! Transport for the p2p network.
//!
//! This module defines a customizable transport layer for peer-to-peer networking.
//! The transport layer has support for DNS(TCP), WebSocket (WS and WSS), authentication using the Noise protocol, and multiplexing using the Yamux protocol.
//! Users can customize various parameters to tailor the transport behavior to their needs.

use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade},
    dns, identity, noise, tcp, websocket, PeerId, Transport,
};
use std::time::Duration;

/// The value of one kibibyte (KiB) in bytes.
pub const KIB: usize = 1024;
/// The value of one mebibyte (MiB) in bytes.
pub const MIB: usize = 1024 * KIB;

/// Builder for creating a customizable transport layer.
pub struct TransportBuilder {
    timeout: Duration,
    yamux_window_size: u32,
    yamux_maximum_buffer_size: usize,
}

impl TransportBuilder {
    /// Create a new [`TransportBuilder`].
    pub fn new() -> TransportBuilder {
        TransportBuilder {
            timeout: Duration::from_secs(20),
            yamux_window_size: 256 * (KIB as u32),
            yamux_maximum_buffer_size: MIB,
        }
    }

    /// Adds a timeout to the setup and protocol upgrade process for all
    /// inbound and outbound connections established through the transport.
    ///
    /// Default: 20 seconds.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the maximum size of the Yamux receive windows.
    ///
    /// Default: 256 KiB
    pub fn yamux_window_size(mut self, yamux_window_size: u32) -> Self {
        self.yamux_window_size = yamux_window_size;
        self
    }

    /// Set the maximum allowed size of the Yamux buffer.
    /// This should be set either to the maximum of all the maximum allowed sizes of messages frames of all
    /// high-level protocols combined, or to some generously high value if you are sure that a maximum
    /// size is enforced on all high-level protocols.
    ///
    /// Default: 1 MiB
    pub fn yamux_maximum_buffer_size(mut self, yamux_maximum_buffer_size: usize) -> Self {
        self.yamux_maximum_buffer_size = yamux_maximum_buffer_size;
        self
    }

    /// Build the base layer of the transport with an identity keypair used for authentication.
    ///
    /// This function constructs the transport by configuring DNS (TCP) as the main transport,
    /// supporting WebSocket protocols, enabling Noise authentication,
    /// and setting up Yamux multiplexing with custom parameters.
    pub fn build(self, keypair: identity::Keypair) -> Boxed<(PeerId, StreamMuxerBox)> {
        // The main transport is DNS(TCP).
        let tcp_config = tcp::Config::new().nodelay(true);
        let tcp_trans = tcp::tokio::Transport::new(tcp_config.clone());
        let dns = dns::TokioDnsConfig::system(tcp_trans).expect("Can construct DNS; qed");

        // Support for WS and WSS.
        let tcp_trans = tcp::tokio::Transport::new(tcp_config);
        let dns_for_wss =
            dns::TokioDnsConfig::system(tcp_trans).expect("Valid config provided; qed");

        let transport = websocket::WsConfig::new(dns_for_wss).or_transport(dns);

        let authentication_config =
            noise::Config::new(&keypair).expect("Can create noise config; qed");

        let multiplexing_config = {
            let mut yamux_config = libp2p::yamux::Config::default();

            // Enable proper flow-control: window updates are only sent when
            // buffered data has been consumed.
            yamux_config.set_window_update_mode(libp2p::yamux::WindowUpdateMode::on_read());
            yamux_config.set_max_buffer_size(self.yamux_maximum_buffer_size);
            yamux_config.set_receive_window_size(self.yamux_window_size);

            yamux_config
        };

        transport
            .upgrade(upgrade::Version::V1Lazy)
            .authenticate(authentication_config)
            .multiplex(multiplexing_config)
            .timeout(self.timeout)
            .boxed()
    }
}
