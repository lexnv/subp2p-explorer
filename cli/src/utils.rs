// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use ip_network::IpNetwork;
use libp2p::{core::upgrade, identity, multiaddr::Protocol, Multiaddr, PeerId, Swarm, Transport};

use crate::filtered_transport::FilteredTransport;
use maxminddb::{geoip2::City, Reader as GeoIpReader};
use primitive_types::H256;
use std::error::Error;
use std::net::IpAddr;
use std::time::Duration;
use subp2p_explorer::{
    discovery::DiscoveryBuilder,
    notifications::{
        behavior::{Notifications, ProtocolsData},
        messages::ProtocolRole,
    },
    peer_behavior::PeerBehaviour,
    Behaviour,
};

/// Translate IP addresses to locations.
pub struct Locator {
    db: maxminddb::Reader<&'static [u8]>,
}

/// The location result of an IP query.
#[derive(Debug)]
pub struct Location {
    pub city: String,
    pub _accuracy_radius: Option<u16>,
    pub _latitude: Option<f64>,
    pub _longitude: Option<f64>,
    pub _metro_code: Option<u16>,
    pub _time_zone: Option<String>,
}

impl Default for Locator {
    fn default() -> Self {
        Self::new()
    }
}

impl Locator {
    const CITY_DATA: &'static [u8] = include_bytes!("../../artifacts/GeoLite2-City.mmdb");

    /// Constructs a new [`Locator`].
    pub fn new() -> Self {
        Self {
            db: GeoIpReader::from_source(Self::CITY_DATA).expect("City data is always valid"),
        }
    }

    /// Geolocate the IP address and return the location.
    pub fn locate(&self, ip: IpAddr) -> Option<Location> {
        let City { city, location, .. } = self.db.lookup(ip).ok()?;

        let city = city
            .as_ref()?
            .names
            .as_ref()?
            .get("en")?
            .to_string()
            .into_boxed_str();

        Some(Location {
            city: city.into_string(),
            _accuracy_radius: location
                .clone()
                .and_then(|loc: maxminddb::geoip2::city::Location| loc.accuracy_radius),
            _latitude: location.clone().and_then(|loc| loc.latitude),
            _longitude: location.clone().and_then(|loc| loc.longitude),
            _metro_code: location.clone().and_then(|loc| loc.metro_code),
            _time_zone: location.and_then(|loc| loc.time_zone.map(|zone| zone.to_string())),
        })
    }
}

/// Build the swarm for the CLI.
pub async fn build_swarm(
    genesis: String,
    bootnodes: Vec<String>,
    query_timeout: Duration,
) -> Result<Swarm<Behaviour>, Box<dyn Error>> {
    // Create a random key for ourselves.
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    tracing::info!("Local peer ID {:?}", local_peer_id);

    let genesis = genesis.trim_start_matches("0x");

    // Parse the provided bootnodes as `PeerId` and `MultiAddress`.
    let bootnodes: Vec<_> = bootnodes
        .iter()
        .map(|bootnode| {
            let parts: Vec<_> = bootnode.split('/').collect();
            let peer = parts.last().expect("Valid bootnode has peer; qed");
            let multiaddress: Multiaddr = bootnode.parse().expect("Valid multiaddress; qed");
            let peer_id: PeerId = peer.parse().expect("Valid peer ID; qed");

            log::info!("Bootnode peer={:?}", peer_id);
            (peer_id, multiaddress)
        })
        .collect();

    // Craft the specific protocol data.
    let protocol_data = ProtocolsData {
        genesis_hash: H256::from_slice(hex::decode(genesis)?.as_slice()),
        node_role: ProtocolRole::FullNode,
    };

    let discovery = DiscoveryBuilder::new()
        .record_ttl(Some(Duration::from_secs(0)))
        .provider_ttl(Some(Duration::from_secs(0)))
        .query_timeout(query_timeout)
        .build(local_peer_id, genesis);

    let peer_info = PeerBehaviour::new(local_key.public());
    let notifications = Notifications::new(protocol_data);

    let tcp_config = libp2p::tcp::Config::new().nodelay(true);

    // Build TCP transport with noise and yamux
    let tcp_transport = libp2p::tcp::tokio::Transport::new(tcp_config.clone())
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(libp2p::noise::Config::new(&local_key).expect("noise config"))
        .multiplex(libp2p::yamux::Config::default())
        .boxed();

    // Wrap with DNS resolution
    let tcp_dns_transport = libp2p::dns::tokio::Transport::system(tcp_transport)
        .expect("DNS transport")
        .boxed();

    // Wrap with our filter to block private IPs
    let filtered_tcp = FilteredTransport::new(tcp_dns_transport).boxed();

    // Build WebSocket transport
    let ws_transport = libp2p::websocket::Config::new(
        libp2p::dns::tokio::Transport::system(libp2p::tcp::tokio::Transport::new(tcp_config))
            .expect("DNS for WS"),
    )
    .upgrade(upgrade::Version::V1Lazy)
    .authenticate(libp2p::noise::Config::new(&local_key).expect("noise config ws"))
    .multiplex(libp2p::yamux::Config::default())
    .boxed();

    // Wrap WebSocket with filter too
    let filtered_ws = FilteredTransport::new(ws_transport).boxed();

    // Combine transports
    let transport = filtered_tcp
        .or_transport(filtered_ws)
        .map(|output, _| match output {
            futures::future::Either::Left(o) => o,
            futures::future::Either::Right(o) => o,
        })
        .boxed();

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_other_transport(|_key| transport)
        .expect("Can construct transport; qed")
        .with_behaviour(|_key| Behaviour {
            notifications,
            peer_info,
            discovery,
        })
        .expect("Can construct behaviour; qed")
        .build();

    // Active set of peers from the kbuckets of kademlia.
    // These are the initial peers for which the queries are performed against.
    for (peer, multiaddress) in &bootnodes {
        swarm
            .behaviour_mut()
            .discovery
            .add_address(peer, multiaddress.clone());
    }

    Ok(swarm)
}

/// Checks if the p2p address is public.
pub fn is_public_address(addr: &Multiaddr) -> bool {
    let ip = match addr.iter().next() {
        Some(Protocol::Ip4(ip)) => IpNetwork::from(ip),
        Some(Protocol::Ip6(ip)) => IpNetwork::from(ip),
        Some(Protocol::Dns(_)) | Some(Protocol::Dns4(_)) | Some(Protocol::Dns6(_)) => return true,
        _ => return false,
    };
    ip.is_global()
}
