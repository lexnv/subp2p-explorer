// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use libp2p::{multiaddr, Multiaddr, PeerId};

/// Get the peerId from a p2p multiaddress.
pub fn get_peer_id(address: &Multiaddr) -> Option<PeerId> {
    match address.iter().last() {
        Some(multiaddr::Protocol::P2p(key)) => Some(key),
        _ => None,
    }
}
