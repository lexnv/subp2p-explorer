// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

mod commands;
mod utils;

use clap::Parser as ClapParser;
use commands::{
    authorities::discover_authorities, bootnodes::verify_bootnodes, discovery::discover_network,
    extrinsics::submit_extrinsics,
};
use std::{error::Error, io::Read, path::PathBuf};

/// Command for interacting with the CLI.
#[derive(Debug, ClapParser)]
enum Command {
    Authorities(Authorities),
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
    /// The number of seconds the discovery process should run for.
    #[clap(long, short, value_parser = parse_duration)]
    timeout: std::time::Duration,
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
    tracing_subscriber::fmt().init();

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
                opts.timeout,
            )
            .await
        }
        Command::VerifyBootnodes(opts) => opts.verify_bootnodes().await,
        Command::Authorities(opts) => {
            discover_authorities(
                opts.url,
                opts.genesis,
                opts.bootnodes,
                opts.timeout,
                opts.address_format,
                opts.raw_output,
            )
            .await
        }
    }
}
