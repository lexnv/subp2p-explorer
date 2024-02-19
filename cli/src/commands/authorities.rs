use std::collections::{HashMap, HashSet};

use codec::Decode;
use futures::StreamExt;
use hex::decode;
pub use jsonrpsee::{
    client_transport::ws::{Url, WsTransportClientBuilder},
    core::client::{Client, ClientT},
    rpc_params,
};

use libp2p::{
    identify::Info,
    kad::{record::Key as KademliaKey, GetRecordOk, KademliaEvent, QueryId, QueryResult},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use multihash_codetable::{Code, MultihashDigest};
use prost::Message;
use subp2p_explorer::{Behaviour, BehaviourEvent};

use crate::utils::build_swarm;

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

fn decode_dht_record(value: Vec<u8>) -> Result<Vec<Multiaddr>, Box<dyn std::error::Error>> {
    let payload = schema::SignedAuthorityRecord::decode(value.as_slice())?;
    let record = schema::AuthorityRecord::decode(payload.record.as_slice())?;

    let addresses: Vec<Multiaddr> = record
        .addresses
        .into_iter()
        .map(|a| a.try_into())
        .collect::<std::result::Result<_, _>>()?;

    Ok(addresses)
}

struct AuthorityDiscovery {
    /// Drive the network behavior.
    swarm: Swarm<Behaviour>,
    /// In flight kademlia queries.
    queries: HashMap<QueryId, sr25519::PublicKey>,
    /// Peer details including protocols, multiaddress.
    peer_details: HashMap<PeerId, Info>,
}

impl AuthorityDiscovery {
    pub fn new(swarm: Swarm<Behaviour>) -> Self {
        AuthorityDiscovery {
            swarm,
            queries: HashMap::with_capacity(1024),
            peer_details: HashMap::with_capacity(1024),
        }
    }

    fn query_kademlia(&mut self, authorities: Vec<sr25519::PublicKey>) {
        // Make a query for every authority.
        for authority in authorities {
            let key = hash_authority_id(&authority);
            let id = self.swarm.behaviour_mut().discovery.get_record(key);
            self.queries.insert(id, authority);
        }
    }

    pub async fn discover(&mut self, authorities: Vec<sr25519::PublicKey>) {
        self.query_kademlia(authorities);

        loop {
            let event = self.swarm.select_next_some().await;

            match event {
                SwarmEvent::Behaviour(BehaviourEvent::Discovery(event)) => match event {
                    KademliaEvent::OutboundQueryProgressed {
                        id,
                        result: QueryResult::GetRecord(record),
                        ..
                    } => {
                        let Some(authority) = self.queries.remove(&id) else {
                            continue;
                        };

                        println!("record; {:?}", record);

                        match record {
                            Ok(GetRecordOk::FoundRecord(peer_record)) => {
                                let value = peer_record.record.value;
                                println!("authority: {:?} value: {:?}", authority, value);

                                let Ok(addresses) = decode_dht_record(value) else {
                                    continue;
                                };
                                println!("Addresses: {:?}\n", addresses);
                            }
                            _ => (),
                        }
                    }
                    _ => (),
                },
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

    let authorities = runtime_api_autorities(url).await?;

    let first = authorities.first().expect("No authorities found");
    let _key = hash_authority_id(first);

    let swarm = build_swarm(genesis.clone(), bootnodes)?;
    let mut authority_discovery = AuthorityDiscovery::new(swarm);

    authority_discovery.discover(authorities).await;

    Ok(())
}
