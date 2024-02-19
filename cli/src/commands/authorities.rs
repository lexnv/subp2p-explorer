use codec::Decode;
pub use jsonrpsee::{
    client_transport::ws::{Url, WsTransportClientBuilder},
    core::client::{Client, ClientT},
    rpc_params,
};

use libp2p::kad::record::Key as KademliaKey;
use multihash_codetable::{Code, MultihashDigest};

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

pub async fn discover_authorities(
    url: String,
    genesis: String,
    bootnodes: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = Url::parse(&url)?;

    let authorities = runtime_api_autorities(url).await?;

    let first = authorities.first().expect("No authorities found");
    let _key = hash_authority_id(first);

    Ok(())
}
