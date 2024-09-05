use std::{collections::HashMap, error::Error};

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use subp2p_explorer_core::{types::peer_id::PeerId, NetworkBackend};

use subp2p_explorer_core::litep2p::Litep2pBackend;

use crate::discovery_backends;
use crate::DiscoverBackendsNetworkOpts;
use crate::DiscoverLocalBackendsNetworkOpts;

pub async fn spawn_network(
    opts: DiscoverLocalBackendsNetworkOpts,
    genesis: String,
) -> Result<(), Box<dyn Error>> {
    tracing::info!("Spawning local network with {} backends", opts.network_size);

    let mut backends: Vec<Litep2pBackend> = (0..opts.network_size)
        .map(|_| subp2p_explorer_core::litep2p::Litep2pBackend::new(genesis.clone()))
        .collect();

    let mut peers = HashMap::new();

    tracing::info!("Connecting backends");

    // Connect the backends in a ring.
    let mut iter = backends.iter_mut();
    let mut current = iter.next().expect("At least one backend; qed");

    while let Some(next) = iter.next() {
        let current_addr = current.listen_addresses().await;
        tracing::info!("Current address: {:?}", current_addr);
        let current_peer =
            PeerId::try_from_multiaddr(&current_addr[0]).expect("Valid peer ID; qed");
        peers.insert(current_peer, current_addr.clone());

        let next_addr = next.listen_addresses().await;
        tracing::info!("Next address: {:?}", next_addr);
        let next_peer = PeerId::try_from_multiaddr(&next_addr[0]).expect("Valid peer ID; qed");
        peers.insert(next_peer, next_addr.clone());

        current.add_known_peer(next_peer, next_addr.clone()).await;
        next.add_known_peer(current_peer, current_addr.clone())
            .await;

        current = next;
    }
    // TODO: Connect the last backend with the first one.

    // Ensure the backends are polled.
    tokio::spawn(async move {
        let backends = backends
            .into_iter()
            .map(|mut backend| async move {
                loop {
                    backend.next().await;
                }
            })
            .collect::<Vec<_>>();

        let mut futures = FuturesUnordered::new();
        futures.extend(backends);

        loop {
            futures.next().await;
        }
    });

    tracing::info!("Starting discovery process");
    discovery_backends::discovery_backends(DiscoverBackendsNetworkOpts {
        num_peers: opts.num_peers,
        backend_type: opts.backend_type,
        data_set: opts.data_set,
        genesis,
        bootnodes: peers
            .values()
            .take(5)
            .map(|addrs| addrs[0].to_string())
            .collect(),
    })
    .await?;

    Ok(())
}
