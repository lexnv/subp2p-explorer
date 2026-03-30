// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use futures::StreamExt;
use libp2p::{
    identify,
    identity,
    swarm::SwarmEvent,
    Multiaddr, Swarm,
};
use std::error::Error;
use std::time::Duration;
use subp2p_explorer::peer_behavior::AGENT;

async fn build_swarm() -> Swarm<identify::Behaviour> {
    let local_key = identity::Keypair::generate_ed25519();

    let behavior = identify::Behaviour::new(
        identify::Config::new("/substrate/1.0".to_string(), local_key.public())
            .with_agent_version(AGENT.to_string())
            .with_cache_size(0),
    );

    let tcp_config = libp2p::tcp::Config::new().nodelay(true);

    libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp_config,
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .expect("Can construct TCP; qed")
        .with_dns()
        .expect("Can construct DNS; qed")
        .with_websocket(libp2p::noise::Config::new, libp2p::yamux::Config::default)
        .await
        .expect("Can construct WebSocket; qed")
        .with_behaviour(|_key| behavior)
        .expect("Can construct behaviour; qed")
        .build()
}

pub async fn dial_peer(
    addresses: Vec<String>,
    timeout: Duration,
) -> Result<(), Box<dyn Error>> {
    let mut swarm = build_swarm().await;

    let num_addresses = addresses.len();
    for addr in &addresses {
        let multiaddr: Multiaddr = addr.parse()?;
        swarm.dial(multiaddr.clone())?;
        println!("Dialing {multiaddr}");
    }

    let mut received = 0usize;

    let result = tokio::time::timeout(timeout, async {
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::Behaviour(event) => match event {
                    identify::Event::Received { peer_id, info, .. } => {
                        println!();
                        println!("Peer: {peer_id}");
                        println!("  Agent Version:    {}", info.agent_version);
                        println!("  Protocol Version: {}", info.protocol_version);
                        println!("  Listen Addresses:");
                        for addr in &info.listen_addrs {
                            println!("    {addr}");
                        }
                        println!("  Observed Address: {}", info.observed_addr);
                        println!("  Protocols:");
                        for proto in &info.protocols {
                            println!("    {proto}");
                        }

                        received += 1;
                        if received >= num_addresses {
                            break;
                        }
                    }
                    identify::Event::Error { peer_id, error, .. } => {
                        println!();
                        println!("Error identifying {peer_id}: {error}");
                    }
                    _ => {}
                },
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    println!("Connection error: {error}");
                }
                _ => {}
            }
        }
    })
    .await;

    if result.is_err() {
        println!();
        println!(
            "Timeout after {}s — received identify from {received}/{num_addresses} address(es).",
            timeout.as_secs()
        );
    }

    Ok(())
}
