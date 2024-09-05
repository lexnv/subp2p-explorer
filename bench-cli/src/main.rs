// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use clap::Parser as ClapParser;
use serde::Serialize;
use std::{error::Error, path::PathBuf};

mod discovery_backends;
mod discovery_local;

/// Command for interacting with the CLI.
#[derive(Debug, ClapParser)]
enum Command {
    Discovery(DiscoverBackendsNetworkOpts),
    DiscoveryLocal(DiscoverLocalBackendsNetworkOpts),
}

#[derive(Debug, Default, clap::ValueEnum, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum BackendType {
    /// Use the `litep2p` backend.
    #[default]
    Litep2p,

    /// Use the `libp2p` backend.
    Libp2p,
}

/// Discover the p2p network.
#[derive(Debug, ClapParser)]
pub struct DiscoverBackendsNetworkOpts {
    /// Hex-encoded genesis hash of the chain.
    ///
    /// For example, "781e4046b4e8b5e83d33dde04b32e7cb5d43344b1f19b574f6d31cbbd99fe738"
    #[clap(long, short)]
    genesis: String,

    /// Bootnodes of the chain, must contain a multiaddress together with the peer ID.
    /// For example, "/ip4/127.0.0.1/tcp/30333/ws/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp".
    #[clap(long, use_value_delimiter = true, value_parser)]
    bootnodes: Vec<String>,

    /// The number of peers discovered after which the discovery process should stop.
    #[clap(long, short)]
    num_peers: usize,

    /// The backend type to use for the discovery process.
    #[clap(long, short)]
    backend_type: BackendType,

    /// The data set to use for the discovery process.
    #[clap(long, value_parser)]
    data_set: Option<PathBuf>,
}

/// Discover the p2p network.
#[derive(Debug, ClapParser)]
pub struct DiscoverLocalBackendsNetworkOpts {
    /// The number of peers to simulate in the network.
    #[clap(long)]
    network_size: usize,

    /// The number of peers discovered after which the discovery process should stop.
    #[clap(long)]
    num_peers: usize,

    /// The backend type to use for the discovery process.
    #[clap(long, short)]
    backend_type: BackendType,

    /// The data set to use for the discovery process.
    #[clap(long, value_parser)]
    data_set: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Command::parse();
    match args {
        Command::Discovery(opts) => discovery_backends::discovery_backends(opts).await,
        Command::DiscoveryLocal(opts) => {
            discovery_local::spawn_network(
                opts,
                "781e4046b4e8b5e83d33dde04b32e7cb5d43344b1f19b574f6d31cbbd99fe738".to_string(),
            )
            .await
        }
    }
}
