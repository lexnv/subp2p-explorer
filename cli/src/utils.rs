// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use ip_network::IpNetwork;
use libp2p::{identity, multiaddr::Protocol, swarm::SwarmBuilder, Multiaddr, PeerId, Swarm};
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
    transport::{TransportBuilder, MIB},
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
    // pub accuracy_radius: Option<u16>,
    // pub latitude: Option<f64>,
    // pub longitude: Option<f64>,
    // pub metro_code: Option<u16>,
    // pub time_zone: Option<String>,
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
        let City { city, .. } = self.db.lookup(ip).ok()?;

        let city = city
            .as_ref()?
            .names
            .as_ref()?
            .get("en")?
            .to_string()
            .into_boxed_str();

        Some(Location {
            city: city.into_string(),
        })

        // Some(Location {
        //     city: city.into_string(),
        //     accuracy_radius: location.clone().map(|loc| loc.accuracy_radius).flatten(),
        //     latitude: location.clone().map(|loc| loc.latitude).flatten(),
        //     longitude: location.clone().map(|loc| loc.longitude).flatten(),
        //     metro_code: location.clone().map(|loc| loc.metro_code).flatten(),
        //     time_zone: location
        //         .map(|loc| loc.time_zone.map(|zone| zone.to_string()))
        //         .flatten(),
        // })
    }
}

/// Build the swarm for the CLI.
pub fn build_swarm(
    genesis: String,
    bootnodes: Vec<String>,
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

    // Create a Switch (swarm) to manage peers and events.
    let mut swarm: Swarm<Behaviour> = {
        let transport = TransportBuilder::new()
            .yamux_maximum_buffer_size(256 * MIB)
            .build(local_key.clone());

        let discovery = DiscoveryBuilder::new()
            .record_ttl(Some(Duration::from_secs(0)))
            .provider_ttl(Some(Duration::from_secs(0)))
            .query_timeout(Duration::from_secs(5 * 60))
            .build(local_peer_id, genesis);

        let peer_info = PeerBehaviour::new(local_key.public());
        let notifications = Notifications::new(protocol_data);

        let behavior = Behaviour {
            notifications,
            peer_info,
            discovery,
        };

        SwarmBuilder::with_tokio_executor(transport, behavior, local_peer_id).build()
    };

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
