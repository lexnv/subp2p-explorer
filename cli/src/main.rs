// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

mod commands;
mod utils;

use clap::Parser as ClapParser;
use commands::{
    authorities::{discover_authorities, resolve_bootnodes},
    authority_check::check_authorities,
    bootnodes::verify_bootnodes,
    dial_peer::dial_peer,
    discovery::discover_network,
    extrinsics::submit_extrinsics,
};
use jsonrpsee::client_transport::ws::Url;
use std::{error::Error, io::Read, path::PathBuf};

/// Command for interacting with the CLI.
#[derive(Debug, ClapParser)]
enum Command {
    Authorities(Authorities),
    AuthorityCheck(AuthorityCheckOpts),
    DialPeer(DialPeerOpts),
    SendExtrinisic(SendExtrinisicOpts),
    DiscoverNetwork(DiscoverNetworkOpts),
    VerifyBootnodes(BootnodesOpts),
}

/// Discover the authorities of the p2p network.
#[derive(Debug, ClapParser)]
pub struct Authorities {
    /// The URL of the chain RPC endpoint.
    #[clap(long, short)]
    url: String,
    /// Hex-encoded genesis hash of the chain.
    ///
    /// For example, "781e4046b4e8b5e83d33dde04b32e7cb5d43344b1f19b574f6d31cbbd99fe738"
    #[clap(long, short)]
    genesis: String,
    /// Bootnodes of the chain, must contain a multiaddress together with the peer ID.
    /// For example, "/ip4/127.0.0.1/tcp/30333/ws/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp".
    #[clap(long, use_value_delimiter = true, value_parser)]
    bootnodes: Vec<String>,
    /// The number of seconds the authority discovery process should run for.
    #[clap(long, short, value_parser = parse_duration)]
    timeout: std::time::Duration,
    /// The address format name of the chain.
    /// Used to display the SS58 address of the authorities.
    ///
    /// For example:
    /// - "polkadot" for Polkadot
    /// - "substrate" for Substrate
    /// - "kusama" for Kusama
    #[clap(long, short)]
    address_format: String,
    /// Print the raw identity list of discovered peers.
    #[clap(long, short)]
    raw_output: bool,
    /// The number of seconds for each individual Kademlia DHT query before it is
    /// considered failed. Lower values free up query slots faster when records
    /// do not exist in the DHT.
    #[clap(long, default_value = "15", value_parser = parse_duration)]
    query_timeout: std::time::Duration,
}

/// Check authority health: discover DHT records, test connectivity per address,
/// and report per-authority and global statistics.
#[derive(Debug, ClapParser)]
pub struct AuthorityCheckOpts {
    /// The URL of the chain RPC endpoint.
    #[clap(long, short)]
    url: String,
    /// Hex-encoded genesis hash of the chain.
    ///
    /// If not provided, the genesis hash is fetched from the RPC endpoint.
    #[clap(long, short)]
    genesis: Option<String>,
    /// Bootnodes of the chain, must contain a multiaddress together with the peer ID.
    ///
    /// If not provided, bootnodes are fetched from the chain spec via the RPC endpoint.
    #[clap(long, use_value_delimiter = true, value_parser)]
    bootnodes: Vec<String>,
    /// The number of seconds for DHT discovery.
    #[clap(long, short, value_parser = parse_duration)]
    timeout: std::time::Duration,
    /// The number of seconds to wait for each individual TCP connection check.
    #[clap(long, short = 'd', default_value = "10", value_parser = parse_duration)]
    dial_timeout: std::time::Duration,
    /// The address format name of the chain (e.g., "polkadot", "kusama").
    ///
    /// If not provided, the SS58 prefix is fetched from the RPC endpoint.
    #[clap(long, short)]
    address_format: Option<String>,
    /// The number of seconds for each individual Kademlia DHT query before it is
    /// considered failed. Lower values free up query slots faster when records
    /// do not exist in the DHT.
    #[clap(long, default_value = "15", value_parser = parse_duration)]
    query_timeout: std::time::Duration,
    /// The RPC endpoint of the chain that hosts on-chain identities
    /// (e.g., the People parachain `wss://polkadot-people-rpc.polkadot.io`).
    ///
    /// When provided, authority display names are resolved from the Identity
    /// pallet on that chain. If omitted, identities are looked up on the
    /// relay chain itself.
    #[clap(long)]
    identity_rpc: Option<String>,
    /// Show only authorities that have failures (no DHT record, unreachable
    /// public addresses, or no public addresses at all).
    #[clap(long)]
    show_failing_only: bool,
    /// Write the full results as a JSON report to the given file path.
    #[clap(long)]
    json: Option<PathBuf>,
}

/// Dial one or more multiaddresses and fetch the identify message from each peer.
#[derive(Debug, ClapParser)]
pub struct DialPeerOpts {
    /// Multiaddresses to dial.
    ///
    /// For example, "/ip4/35.75.15.11/tcp/30333" or
    /// "/dns/example.com/tcp/30333/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp".
    #[clap(long, use_value_delimiter = true, value_parser)]
    address: Vec<String>,
    /// The number of seconds to wait for responses before giving up.
    #[clap(long, short, default_value = "30", value_parser = parse_duration)]
    timeout: std::time::Duration,
}

/// Send extrinsic on the p2p network.
#[derive(Debug, ClapParser)]
pub struct SendExtrinisicOpts {
    /// Hex-encoded genesis hash of the chain.
    ///
    /// For example, "781e4046b4e8b5e83d33dde04b32e7cb5d43344b1f19b574f6d31cbbd99fe738"
    #[clap(long, short)]
    genesis: String,
    /// Bootnodes of the chain, must contain a multiaddress together with the peer ID.
    /// For example, "/ip4/127.0.0.1/tcp/30333/ws/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp".
    #[clap(long, use_value_delimiter = true, value_parser)]
    bootnodes: Vec<String>,
    /// Hex-encoded scale-encoded vector of extrinsics to submit to peers.
    #[clap(long, short)]
    extrinsics: String,
}

/// Discover the p2p network.
#[derive(Debug, ClapParser)]
pub struct DiscoverNetworkOpts {
    /// Hex-encoded genesis hash of the chain.
    ///
    /// For example, "781e4046b4e8b5e83d33dde04b32e7cb5d43344b1f19b574f6d31cbbd99fe738"
    #[clap(long, short)]
    genesis: String,
    /// Bootnodes of the chain, must contain a multiaddress together with the peer ID.
    /// For example, "/ip4/127.0.0.1/tcp/30333/ws/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp".
    #[clap(long, use_value_delimiter = true, value_parser)]
    bootnodes: Vec<String>,
    /// The number of cities to print in decreasing order by the number of peers.
    ///
    /// Defaults to 10.
    #[clap(long, short)]
    cities: Option<usize>,
    /// Print the raw list of peers with geolocation.
    #[clap(long, short)]
    raw_geolocation: bool,
    /// Show only authorities.
    #[clap(long, short)]
    only_authorities: bool,
    /// Print every peer that responded to the identify protocol, along with
    /// its agent version and announced role (if any).
    #[clap(long)]
    identified: bool,
    /// The number of seconds the discovery process should run for.
    #[clap(long, short, value_parser = parse_duration)]
    timeout: std::time::Duration,
    /// The number of seconds for each individual Kademlia DHT query before it is
    /// considered failed. Lower values free up query slots faster when records
    /// do not exist in the DHT.
    #[clap(long, default_value = "15", value_parser = parse_duration)]
    query_timeout: std::time::Duration,
}

fn parse_duration(arg: &str) -> Result<std::time::Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(std::time::Duration::from_secs(seconds))
}

/// Verify bootnodes are reachable on the p2p network.
///
/// This will attempt to connect ot each provided bootnode and
#[derive(Debug, ClapParser)]
pub struct BootnodesOpts {
    /// Bootnodes of the chain, must contain a multiaddress together with the peer ID.
    ///
    /// For example, "/ip4/127.0.0.1/tcp/30333/ws/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp".
    #[clap(long, use_value_delimiter = true, value_parser)]
    bootnodes: Vec<String>,
    /// Hex-encoded genesis hash of the chain.
    ///
    /// When this is provided, the supported p2p protocols of the bootnodes will be
    /// verified against the provided genesis hash.
    ///
    /// For example, "781e4046b4e8b5e83d33dde04b32e7cb5d43344b1f19b574f6d31cbbd99fe738"
    #[clap(long, short)]
    genesis: Option<String>,

    /// Verify the bootnodes using the provided chain spec.
    ///
    /// This is incompatible with `--bootnodes`.
    #[clap(long, value_parser)]
    chain_spec: Option<PathBuf>,
}

impl BootnodesOpts {
    /// Verify the bootnodes.
    pub async fn verify_bootnodes(&self) -> Result<(), Box<dyn Error>> {
        match (&self.bootnodes, &self.genesis, &self.chain_spec) {
            (bootnodes, _, Some(_)) if !bootnodes.is_empty() => {
                Err("`--bootnodes` is incompatible with `--chain-spec`".into())
            }
            (bootnodes, _, None) => verify_bootnodes(bootnodes.clone(), self.genesis.clone()).await,
            (_, genesis, Some(spec)) => {
                let mut file = std::fs::File::open(spec)?;
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)?;

                let spec = serde_json::from_slice::<serde_json::Value>(&bytes)
                    .map_err(|e| format!("Invalid chain spec: {}", e))?;

                let bootnodes = spec
                    .get("bootNodes")
                    .ok_or("Missing `bootNodes`")?
                    .as_array()
                    .ok_or("Invalid `bootNodes` format, expected array")?
                    .iter()
                    .map(|node| {
                        node.as_str()
                            .map(|s| s.to_string())
                            .ok_or("Invalid `bootNodes` format, expected string")
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                verify_bootnodes(bootnodes, genesis.clone()).await
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Command::parse();
    match args {
        Command::SendExtrinisic(opts) => {
            submit_extrinsics(opts.genesis, opts.bootnodes, opts.extrinsics).await
        }
        Command::DiscoverNetwork(opts) => {
            discover_network(
                opts.genesis,
                opts.bootnodes,
                opts.cities,
                opts.raw_geolocation,
                opts.only_authorities,
                opts.identified,
                opts.timeout,
                opts.query_timeout,
            )
            .await
        }
        Command::DialPeer(opts) => dial_peer(opts.address, opts.timeout).await,
        Command::VerifyBootnodes(opts) => opts.verify_bootnodes().await,
        Command::Authorities(opts) => {
            let rpc_url = Url::parse(&opts.url)?;
            let bootnodes =
                resolve_bootnodes(&rpc_url, opts.bootnodes, &mut std::io::stdout()).await?;
            discover_authorities(
                opts.url,
                opts.genesis,
                bootnodes,
                opts.timeout,
                opts.address_format,
                opts.raw_output,
                opts.query_timeout,
            )
            .await
            .map(|_| ())
        }
        Command::AuthorityCheck(opts) => {
            check_authorities(
                opts.url,
                opts.genesis,
                opts.bootnodes,
                opts.timeout,
                opts.dial_timeout,
                opts.address_format,
                opts.query_timeout,
                opts.identity_rpc,
                opts.show_failing_only,
                opts.json,
            )
            .await
        }
    }
}
