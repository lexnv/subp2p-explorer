use std::collections::{HashMap, HashSet};
use std::error::Error;

use futures::{Stream, StreamExt};
use subp2p_explorer_core::NetworkBackend;
use subp2p_explorer_core::{
    types::{multiaddr::Multiaddr, peer_id::PeerId},
    NetworkEvent,
};

use crate::DiscoverBackendsNetworkOpts;

/// This is the main driver of the Kademlia discovery process.
pub async fn discovery<Backend>(
    mut backend: Backend,
    bootnodes: Vec<(PeerId, Multiaddr)>,
    num_peers: usize,
) -> Result<(), Box<dyn Error>>
where
    Backend: NetworkBackend + Stream<Item = NetworkEvent> + Unpin,
{
    let mut peers_data = HashMap::new();
    let mut queries = HashMap::new();
    let mut query_times = Vec::with_capacity(1024);
    let mut num_queries = 0;

    for (peer_id, address) in bootnodes {
        backend.add_known_peer(peer_id, vec![address]).await;
    }

    log::info!("Discovering peers...");
    for _ in 0..10 {
        let query_id = backend.find_node(PeerId::random()).await;
        queries.insert(query_id, std::time::Instant::now());
        num_queries += 1;
    }

    while let Some(event) = backend.next().await {
        match event {
            NetworkEvent::PeerIdentified {
                peer,
                listen_addresses,
                ..
            } => {
                let entry = peers_data.entry(peer).or_insert_with(|| HashSet::new());
                listen_addresses.into_iter().for_each(|address| {
                    entry.insert(address);
                });
            }
            NetworkEvent::FindNode {
                peers, query_id, ..
            } => {
                if let Some(res) = queries.remove(&query_id) {
                    log::info!(
                        "    Kademlia query finished query={:?} time={:?}",
                        query_id,
                        res.elapsed()
                    );
                    query_times.push(res.elapsed());
                }

                peers.into_iter().for_each(|(peer, addresses)| {
                    let entry = peers_data.entry(peer).or_insert_with(|| HashSet::new());
                    addresses.into_iter().for_each(|address| {
                        entry.insert(address);
                    });
                });
            }
        }

        log::info!("Discovered {}/{} peers", peers_data.len(), num_peers);

        if peers_data.len() >= num_peers {
            break;
        }

        while queries.len() < 50 {
            let query_id = backend.find_node(PeerId::random()).await;
            queries.insert(query_id, std::time::Instant::now());
            num_queries += 1;
        }
    }

    log::info!("Queries completed: {} / {}", query_times.len(), num_queries);

    if query_times.is_empty() {
        log::info!("No queries were completed");
        return Ok(());
    }

    let average_query_time =
        query_times.iter().sum::<std::time::Duration>() / query_times.len() as u32;
    log::info!("Average query time: {:?}", average_query_time);

    Ok(())
}

pub async fn discovery_backends(opts: DiscoverBackendsNetworkOpts) -> Result<(), Box<dyn Error>> {
    // Parse the provided bootnodes as `PeerId` and `MultiAddress`.
    let bootnodes: Vec<_> = opts
        .bootnodes
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

    let now = std::time::Instant::now();
    match opts.backend_type {
        crate::BackendType::Litep2p => {
            let backend = subp2p_explorer_core::litep2p::Litep2pBackend::new(opts.genesis);

            discovery(backend, bootnodes, opts.num_peers).await?;
        }
        crate::BackendType::Libp2p => {
            let backend = subp2p_explorer_core::libp2p::Libp2pBackend::new(opts.genesis).await;

            discovery(backend, bootnodes, opts.num_peers).await?;
        }
    };

    log::info!("Discovery took {:?}", now.elapsed());

    Ok(())
}