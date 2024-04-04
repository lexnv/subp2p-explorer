// Copyright 2023 Alexandru Vasile
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

use codec::Decode;
use libp2p::kad::record::Key as KademliaKey;
use libp2p::{Multiaddr, PeerId};
use multihash_codetable::{Code, MultihashDigest};
use prost::Message;
use std::collections::HashSet;

use crate::util::crypto::sr25519;
use crate::util::p2p::get_peer_id;

/// Protobuf schema for decoding the authority records from the DHT.
mod schema {
    include!(concat!(env!("OUT_DIR"), "/authority_discovery_v2.rs"));
}

/// Hash the authority ID to obtain the kademlia key at which the record
/// of the authority is stored on the p2p network.
pub fn hash_authority_id(id: &[u8]) -> KademliaKey {
    KademliaKey::new(&Code::Sha2_256.digest(id).digest())
}

/// Decode the DHT payload and verify the signatures.
///
/// The DHT payload is composed:
///  - `record` - The authority record containing the addresses of the authority.
///  - `auth_signature` - The signature of the authority over the `record`.
///  - `peer_signature` - The signature of the peer over the `record`.
///
/// The record must contain at least one address in order to discover the peer
/// identity of the authority.
pub fn decode_dht_record(
    value: Vec<u8>,
    authority_id: &sr25519::PublicKey,
) -> Result<(PeerId, Vec<Multiaddr>), Box<dyn std::error::Error>> {
    // Decode and verify the authority signature.
    let payload = schema::SignedAuthorityRecord::decode(value.as_slice())?;
    let auth_signature = sr25519::Signature::decode(&mut &payload.auth_signature[..])?;
    if !sr25519::verify(&auth_signature, &payload.record, &authority_id) {
        return Err("Cannot verify DHT payload".into());
    }

    // Extract the P2P multiaddresses from the prvoided record.
    let record = schema::AuthorityRecord::decode(payload.record.as_slice())?;
    let addresses: Vec<Multiaddr> = record
        .addresses
        .into_iter()
        .map(|a| a.try_into())
        .collect::<std::result::Result<_, _>>()?;

    // At least one address must be provided and all must point to the same peerId.
    if addresses.is_empty() {
        return Err("No addresses found in the DHT record".into());
    }
    let peer_ids: HashSet<_> = addresses.iter().filter_map(get_peer_id).collect();
    if peer_ids.len() != 1 {
        return Err(format!(
            "All addresses must point to the same peerId: {:?}",
            addresses
        )
        .into());
    }

    let peer_id = peer_ids
        .iter()
        .next()
        .expect("At least one peerId; qed")
        .clone();

    // Verify peer signature.
    let Some(peer_signature) = payload.peer_signature else {
        return Err("Payload is not signed".into());
    };
    let public_key = libp2p::identity::PublicKey::try_decode_protobuf(&peer_signature.public_key)?;
    if peer_id != public_key.to_peer_id() {
        return Err("PeerId does not match the public key".into());
    }
    if !public_key.verify(&payload.record.as_slice(), &peer_signature.signature) {
        return Err("Peer signature verification failed".into());
    }

    Ok((peer_id, addresses))
}
