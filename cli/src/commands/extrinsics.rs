// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use crate::utils::build_swarm;
use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use std::collections::HashMap;
use std::error::Error;
use subp2p_explorer::{
    notifications::behavior::NotificationsToSwarm, peer_behavior::PeerInfoEvent, BehaviourEvent,
    TRANSACTIONS_INDEX,
};

/// Submit extrinsics on the p2p network.
pub async fn submit_extrinsics(
    genesis: String,
    bootnodes: Vec<String>,
    extrinsics: String,
) -> Result<(), Box<dyn Error>> {
    let mut swarm = build_swarm(genesis, bootnodes)?;
    let payload = hex::decode(extrinsics.trim_start_matches("0x"))?;

    // Perform the kademlia bootstrap.
    let local_peer_id = *swarm.local_peer_id();
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
