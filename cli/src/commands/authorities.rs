use crate::utils::build_swarm;
use codec::Decode;
use futures::StreamExt;
use jsonrpsee::{
    client_transport::ws::{Url, WsTransportClientBuilder},
    core::client::{Client, ClientT},
    rpc_params,
};
use libp2p::{
    identify::Info,
    identity::{self, Keypair},
    kad::{record::Key as KademliaKey, GetRecordOk, KademliaEvent, QueryId, QueryResult},
    multiaddr,
    swarm::{DialError, SwarmEvent},
    Multiaddr, PeerId, Swarm,
};
use multihash_codetable::{Code, MultihashDigest};
use prost::Message;
use std::collections::{HashMap, HashSet};
use subp2p_explorer::{
    peer_behavior::PeerInfoEvent,
    transport::{TransportBuilder, MIB},
    Behaviour, BehaviourEvent,
};

const _POLKADOT_URL: &str = "wss://rpc.polkadot.io:443";

pub async fn client(url: Url) -> Result<Client, Box<dyn std::error::Error>> {
    let (sender, receiver) = WsTransportClientBuilder::default().build(url).await?;

    Ok(Client::builder()
        .max_buffer_capacity_per_subscription(4096)
        .build_with_tokio(sender, receiver))
}

mod sr25519 {
    /// Public key for sr25519 keypair implementation.
    pub type PublicKey = [u8; 32];
}

async fn runtime_api_autorities(
    url: Url,
) -> Result<Vec<sr25519::PublicKey>, Box<dyn std::error::Error>> {
    let client = client(url).await?;

    // State call provides the result hex-encoded.
    let raw: String = client
        .request(
            "state_call",
            rpc_params!["AuthorityDiscoveryApi_authorities", "0x"],
        )
        .await?;
    let raw = raw
        .strip_prefix("0x")
        .expect("Substrate API returned invalid hex");

    let bytes = hex::decode(&raw)?;

    let authorities: Vec<sr25519::PublicKey> = Decode::decode(&mut &bytes[..])?;
    Ok(authorities)
}

fn hash_authority_id(id: &[u8]) -> KademliaKey {
    KademliaKey::new(&Code::Sha2_256.digest(id).digest())
}

mod schema {
    include!(concat!(env!("OUT_DIR"), "/authority_discovery_v2.rs"));
}

fn get_peer_id(address: &Multiaddr) -> Option<PeerId> {
    match address.iter().last() {
        Some(multiaddr::Protocol::P2p(key)) => Some(key),
        _ => None,
    }
}

fn decode_dht_record(
    value: Vec<u8>,
) -> Result<(PeerId, Vec<Multiaddr>), Box<dyn std::error::Error>> {
    let payload = schema::SignedAuthorityRecord::decode(value.as_slice())?;
    let record = schema::AuthorityRecord::decode(payload.record.as_slice())?;

    let addresses: Vec<Multiaddr> = record
        .addresses
        .into_iter()
        .map(|a| a.try_into())
        .collect::<std::result::Result<_, _>>()?;

    if addresses.is_empty() {
        return Err("No addresses found in the DHT record".into());
    }

    let peer_ids: HashSet<_> = addresses.iter().filter_map(get_peer_id).collect();
    if peer_ids.len() != 1 {
        return Err(format!(
            "All addresses must point to the same peerId: {:?}",
            addresses
        )
        .into());
    }

    let peer_id = peer_ids
        .iter()
        .next()
        .expect("At least one peerId; qed")
        .clone();

    Ok((peer_id, addresses))
}

struct AuthorityDiscovery {
    /// Drive the network behavior.
    swarm: Swarm<Behaviour>,
    /// In flight kademlia queries.
    queries: HashMap<QueryId, sr25519::PublicKey>,
    /// In flight kademlia queries.
    queries_discovery: HashSet<QueryId>,
    /// Peer details including protocols, multiaddress from the identify protocol.
    peer_info: HashMap<PeerId, Info>,
    /// Peer details obtained from the DHT.
    peer_details: HashMap<PeerId, PeerDetails>,
}

#[derive(Clone)]
struct PeerDetails {
    /// Authority ID from the runtime API.
    authority_id: sr25519::PublicKey,
    /// Discovered from the DHT.
    addresses: Vec<Multiaddr>,
}

impl AuthorityDiscovery {
    pub fn new(swarm: Swarm<Behaviour>) -> Self {
        AuthorityDiscovery {
            swarm,
            queries: HashMap::with_capacity(1024),
            queries_discovery: HashSet::with_capacity(1024),
            peer_info: HashMap::with_capacity(1024),
            peer_details: HashMap::with_capacity(1024),
        }
    }

    fn query_dht_records<'key>(
        &mut self,
        authorities: impl IntoIterator<Item = &'key sr25519::PublicKey>,
    ) {
        // Make a query for every authority.
        for authority in authorities {
            let key = hash_authority_id(authority);
            let id = self.swarm.behaviour_mut().discovery.get_record(key);
            self.queries.insert(id, authority.clone());
        }
    }

    fn query_peer_info(&mut self) {
        const MAX_QUERIES: usize = 128;

        let peers = self.peer_details.keys().cloned().filter_map(|peer| {
            if self.peer_info.contains_key(&peer) {
                None
            } else {
                Some(peer)
            }
        });

        if self.queries_discovery.len() < MAX_QUERIES {
            let query_num = MAX_QUERIES - self.queries_discovery.len();
            for peer in peers.take(query_num) {
                self.queries_discovery
                    .insert(self.swarm.behaviour_mut().discovery.get_closest_peers(peer));
            }
        }
    }

    pub async fn discover(&mut self, authorities: Vec<sr25519::PublicKey>) {
        let expected_results = authorities.len();

        const MAX_QUERIES: usize = 16;

        // At most 32 queries at a time.
        self.query_dht_records(authorities.iter().take(MAX_QUERIES));
        let mut authorities_iter = authorities.iter().skip(MAX_QUERIES);

        let mut finished_records = false;

        loop {
            let event = self.swarm.select_next_some().await;
            match event {
                // Discovery DHT record.
                SwarmEvent::Behaviour(behavior_event) => match behavior_event {
                    BehaviourEvent::Discovery(KademliaEvent::OutboundQueryProgressed {
                        id,
                        result: QueryResult::GetRecord(record),
                        ..
                    }) => {
                        let Some(authority) = self.queries.remove(&id) else {
                            continue;
                        };

                        match record {
                            Ok(GetRecordOk::FoundRecord(peer_record)) => {
                                let value = peer_record.record.value;

                                let Ok((peer_id, addresses)) = decode_dht_record(value) else {
                                    println!(" Decoding DHT failed for authority {:?}", authority);
                                    continue;
                                };

                                println!(
                                    "{}/{} authority: {:?} peer_id {:?} Addresses: {:?}",
                                    self.peer_details.len() + 1,
                                    expected_results,
                                    authority,
                                    peer_id,
                                    addresses
                                );

                                self.peer_details.insert(
                                    peer_id,
                                    PeerDetails {
                                        authority_id: authority,
                                        addresses: addresses,
                                    },
                                );

                                // Add more DHT queries.
                                if self.queries.len() < MAX_QUERIES {
                                    if let Some(next) = authorities_iter.next() {
                                        self.query_dht_records(std::iter::once(next));
                                    };
                                }

                                if self.peer_details.len() == expected_results {
                                    println!("All authorities discovered from DHT");

                                    let discovered = self
                                        .peer_details
                                        .keys()
                                        .filter_map(|peer| self.peer_info.get(peer))
                                        .count();
                                    println!(
                                        "Fully discovered at the moment {}/{}",
                                        discovered, expected_results
                                    );

                                    for peer in self.peer_details.keys() {
                                        if self.peer_info.contains_key(peer) {
                                            let _ = self.swarm.disconnect_peer_id(peer.clone());
                                        }
                                    }

                                    self.query_peer_info();
                                    finished_records = true;
                                }
                            }
                            _ => (),
                        }
                    }

                    BehaviourEvent::Discovery(KademliaEvent::OutboundQueryProgressed {
                        id,
                        result: QueryResult::GetClosestPeers(_),
                        ..
                    }) => {
                        if finished_records {
                            println!(" Discovered closes peers of {:?}", id);
                        }

                        self.queries_discovery.remove(&id);
                        self.query_peer_info();
                    }

                    BehaviourEvent::PeerInfo(info_event) => {
                        match info_event {
                            PeerInfoEvent::Identified { peer_id, info } => {
                                if finished_records {
                                    let discovered = self
                                        .peer_details
                                        .keys()
                                        .filter_map(|peer| self.peer_info.get(peer))
                                        .count();

                                    println!(
                                        " {}/{} Info event {:?}",
                                        discovered, expected_results, peer_id
                                    );
                                }

                                // Save the record.
                                self.peer_info.insert(peer_id, info);
                            }
                        };
                    }
                    _ => (),
                },

                _ => (),
            }
        }
    }
}

/// Reach a single peer and query the identify protocol.
///
/// # Example
///
/// The following address is taken from the DHT.
/// However, the address cannot be reached directly.
/// For this to work, we'd need to implement NAT hole punching.
///
/// ```rust
/// let addr =
///     "/ip4/34.92.86.244/tcp/40333/p2p/12D3KooWKxsprneVYQxxPnPUwDA5p2huuCbZCNyuSHTmKDv3vT2n";
/// let addr: Multiaddr = addr.parse().expect("Valid multiaddress; qed");
/// let peer_id = get_peer_id(&addr);
/// let info = PeerInfo::new(local_key.clone(), vec![addr]);
/// let info = info.discover().await;
/// println!("Peer={:?} version={:?}", peer_id, info);
/// ```
struct PeerInfo {
    swarm: Swarm<libp2p::identify::Behaviour>,
}

impl PeerInfo {
    pub fn new(local_key: Keypair, addresses: Vec<Multiaddr>) -> Self {
        // "/ip4/144.76.115.244/tcp/30333/p2p/12D3KooWKR7TX55EnZ6L6FUHfuZKAEgkL8ffE3KFYqnHZUysSVrW"
        let mut swarm: Swarm<libp2p::identify::Behaviour> = {
            let transport = TransportBuilder::new()
                .yamux_maximum_buffer_size(256 * MIB)
                .build(local_key.clone());

            let identify_config =
                libp2p::identify::Config::new("/substrate/1.0".to_string(), local_key.public())
                    .with_agent_version("subp2p-identify".to_string())
                    // Do not cache peer info.
                    .with_cache_size(0);
            let identify = libp2p::identify::Behaviour::new(identify_config);

            let local_peer_id = PeerId::from(local_key.public());
            libp2p::swarm::SwarmBuilder::with_tokio_executor(transport, identify, local_peer_id)
                .build()
        };

        // These are the initial peers for which the queries are performed against.
        for multiaddress in &addresses {
            let res = swarm.dial(multiaddress.clone());
        }

        PeerInfo { swarm }
    }

    pub async fn discover(mut self) -> Result<Info, DialError> {
        loop {
            let event = self.swarm.select_next_some().await;

            match event {
                SwarmEvent::Behaviour(behavior) => match behavior {
                    libp2p::identify::Event::Received { info, .. } => {
                        return Ok(info);
                    }
                    _ => (),
                },

                SwarmEvent::OutgoingConnectionError { error, .. } => return Err(error),

                _ => (),
            }
        }
    }
}

pub async fn discover_authorities(
    url: String,
    genesis: String,
    bootnodes: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = Url::parse(&url)?;

    // Extract the authorities from the runtime API.
    let authorities = runtime_api_autorities(url).await?;

    // Perform DHT queries to find the authorities on the network.
    // Then, record the addresses of the authorities and the responses
    // from the identify protocol.
    let swarm = build_swarm(genesis.clone(), bootnodes)?;
    let mut authority_discovery = AuthorityDiscovery::new(swarm);
    authority_discovery.discover(authorities).await;

    println!("Finished discovery");

    // Some authorities are not reachable directly, ensure we double check them.
    let local_key = identity::Keypair::generate_ed25519();

    let missing_info = authority_discovery
        .peer_details
        .iter()
        .filter(|(peer, _details)| !authority_discovery.peer_info.contains_key(peer))
        .collect::<Vec<_>>();

    for (peer_id, details) in missing_info {
        let info = PeerInfo::new(local_key.clone(), details.addresses.clone());
        let info = info.discover().await;
        println!("Peer={:?} dial_result={:?}", peer_id, info);
    }

    Ok(())
}
