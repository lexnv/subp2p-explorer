// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

mod commands;
mod utils;

use clap::Parser as ClapParser;
use commands::{discovery::discover_network, extrinsics::submit_extrinsics};
use std::error::Error;

/// Command for interacting with the CLI.
#[derive(Debug, ClapParser)]
enum Command {
    SendExtrinisic(SendExtrinisicOpts),
    DiscoverNetwork(DiscoverNetworkOpts),
    VerifyBootnodes(BootnodesOpts),
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt().init();

    let args = Command::parse();
    match args {
        Command::SendExtrinisic(opts) => {
            submit_extrinsics(opts.genesis, opts.bootnodes, opts.extrinsics).await
        }
        Command::DiscoverNetwork(opts) => discover_network(opts.genesis, opts.bootnodes).await,
        Command::VerifyBootnodes(_opts) => Ok(()),
    }
}
