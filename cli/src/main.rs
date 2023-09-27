// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use subp2p_explorer::{
    discovery::DiscoveryBuilder,
    notifications::{
        behavior::{Notifications, NotificationsToSwarm, ProtocolsData},
        messages::ProtocolRole,
    },
    peer_behavior::{PeerBehaviour, PeerInfoEvent},
    transport::{TransportBuilder, MIB},
    Behaviour, BehaviourEvent, TRANSACTIONS_INDEX,
};

use clap::Parser as ClapParser;
use futures::StreamExt;
use libp2p::{
    identity,
    swarm::{SwarmBuilder, SwarmEvent},
    Multiaddr, PeerId, Swarm,
};
use primitive_types::H256;
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;

/// Command for interacting with the CLI.
#[derive(Debug, ClapParser)]
enum Command {
    SendExtrinisic(SendExtrinisicOpts),
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

async fn submit_extrinsics(
    genesis: String,
    bootnodes: Vec<String>,
    extrinsics: String,
) -> Result<(), Box<dyn Error>> {
    if bootnodes.is_empty() {
        panic!("Expected at least one bootnode");
    }

    // Create a random key for ourselves.
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    tracing::info!("Local peer ID {:?}", local_peer_id);

    let genesis = genesis.trim_start_matches("0x");

    let payload = hex::decode(extrinsics.trim_start_matches("0x"))?;

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

    // Perform the kademlia bootstrap.
    let _query_id = swarm
        .behaviour_mut()
        .discovery
        .get_closest_peers(local_peer_id);

    // Keep track of protocol handlers to submit messages.
    let mut protocol_senders = HashMap::new();
    // Close after 30 notifications.
    let mut close_after = 30;
    loop {
        let event = swarm.select_next_some().await;

        match event {
            SwarmEvent::Behaviour(BehaviourEvent::Notifications(tx)) => match tx {
                NotificationsToSwarm::CustomProtocolOpen {
                    peer_id,
                    received_handshake,
                    inbound,
                    index,
                    sender,
                } => {
                    log::info!(
                        "Protocol open peer={:?} index={:?} handshake={:?} inbound={:?}",
                        peer_id,
                        received_handshake,
                        inbound,
                        index
                    );

                    protocol_senders.insert((peer_id, index), sender);
                }
                NotificationsToSwarm::CustomProtocolClosed { peer_id, index } => {
                    log::info!("Protocol closed peer={:?} index={:?}", peer_id, index);
                }
                NotificationsToSwarm::Notification {
                    peer_id,
                    message,
                    index,
                } => {
                    if close_after == 0 {
                        break;
                    }
                    close_after -= 1;

                    log::info!(
                        "Protocol notification peer={:?} index={:?} message={:?}",
                        index,
                        peer_id,
                        message
                    );

                    if let Some(sender) = protocol_senders.get_mut(&(peer_id, TRANSACTIONS_INDEX)) {
                        log::info!("Submit transaction for peer={:?}", peer_id);

                        let _ = sender.start_send(payload.clone());
                    }
                }
            },
            SwarmEvent::Behaviour(BehaviourEvent::PeerInfo(info_event)) => match info_event {
                PeerInfoEvent::Identified { peer_id, info } => {
                    log::info!("Peer identified peer_id={:?} info={:?}", peer_id, info);
                }
            },

            _ => (),
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt().init();

    let args = Command::parse();
    match args {
        Command::SendExtrinisic(opts) => {
            submit_extrinsics(opts.genesis, opts.bootnodes, opts.extrinsics).await
        }
    }
}
