use crate::commands::authorities::client;
use codec::{Compact, Decode, Encode};
use jsonrpsee::{client_transport::ws::Url, core::client::ClientT, rpc_params};
use serde::Deserialize;
use std::collections::HashMap;
use std::hash::Hasher;
use std::io::Write;
use subp2p_explorer::util::crypto::sr25519;

fn twox_128(data: &[u8]) -> [u8; 16] {
    let hash0 = {
        let mut h = twox_hash::XxHash64::with_seed(0);
        h.write(data);
        h.finish()
    };
    let hash1 = {
        let mut h = twox_hash::XxHash64::with_seed(1);
        h.write(data);
        h.finish()
    };
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&hash0.to_le_bytes());
    out[8..].copy_from_slice(&hash1.to_le_bytes());
    out
}

fn twox_64(data: &[u8]) -> [u8; 8] {
    let mut h = twox_hash::XxHash64::with_seed(0);
    h.write(data);
    h.finish().to_le_bytes()
}

fn blake2_128(data: &[u8]) -> [u8; 16] {
    let hash = blake2b_simd::Params::new().hash_length(16).hash(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(hash.as_bytes());
    out
}

fn storage_key_twox64concat(pallet: &str, item: &str, encoded_key: &[u8]) -> String {
    let mut key = Vec::with_capacity(32 + 8 + encoded_key.len());
    key.extend_from_slice(&twox_128(pallet.as_bytes()));
    key.extend_from_slice(&twox_128(item.as_bytes()));
    key.extend_from_slice(&twox_64(encoded_key));
    key.extend_from_slice(encoded_key);
    format!("0x{}", hex::encode(key))
}

fn storage_key_blake2_128concat(pallet: &str, item: &str, encoded_key: &[u8]) -> String {
    let mut key = Vec::with_capacity(32 + 16 + encoded_key.len());
    key.extend_from_slice(&twox_128(pallet.as_bytes()));
    key.extend_from_slice(&twox_128(item.as_bytes()));
    key.extend_from_slice(&blake2_128(encoded_key));
    key.extend_from_slice(encoded_key);
    format!("0x{}", hex::encode(key))
}

/// `Session::KeyOwner((KeyTypeId("audi"), authority_key))`.
fn storage_key_session_key_owner(authority_key: &sr25519::PublicKey) -> String {
    let encoded = (*b"audi", authority_key.to_vec()).encode();
    storage_key_twox64concat("Session", "KeyOwner", &encoded)
}

/// `Identity::IdentityOf(account)`.
fn storage_key_identity_of(account: &[u8; 32]) -> String {
    storage_key_twox64concat("Identity", "IdentityOf", account)
}

/// `Identity::SuperOf(account)`.
fn storage_key_super_of(account: &[u8; 32]) -> String {
    storage_key_blake2_128concat("Identity", "SuperOf", account)
}

/// Skip a SCALE-encoded identity `Data` enum value.
///
/// Variant layout: 0=None, 1..=33=Raw(0..32 bytes), 34..=37=Hash(32 bytes)
fn skip_data(input: &mut &[u8]) -> Option<()> {
    if input.is_empty() {
        return None;
    }
    let variant = input[0];
    *input = &input[1..];
    let skip = match variant {
        0 => 0,
        1..=33 => (variant - 1) as usize,
        34..=37 => 32,
        _ => return None,
    };
    if input.len() < skip {
        return None;
    }
    *input = &input[skip..];
    Some(())
}

fn decode_data_as_string(input: &mut &[u8]) -> Option<String> {
    if input.is_empty() {
        return None;
    }
    let variant = input[0];
    *input = &input[1..];
    match variant {
        0 => None,
        1..=33 => {
            let len = (variant - 1) as usize;
            if input.len() < len {
                return None;
            }
            let bytes = &input[..len];
            *input = &input[len..];
            let s = String::from_utf8_lossy(bytes).into_owned();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }
        34..=37 => {
            if input.len() < 32 {
                return None;
            }
            *input = &input[32..];
            None
        }
        _ => None,
    }
}

fn skip_judgement(input: &mut &[u8]) -> Option<()> {
    if input.is_empty() {
        return None;
    }
    let variant = input[0];
    *input = &input[1..];
    match variant {
        0 | 2..=6 => Some(()),
        1 => Compact::<u128>::decode(input).ok().map(|_| ()),
        _ => None,
    }
}

/// Extract the display name from a SCALE-encoded `Registration` value.
///
/// Handles both IdentityInfo layouts:
///  - simple (People chains): Registration { judgements, deposit, display, ... }
///  - legacy (relay chains):  Registration { judgements, deposit, additional, display, ... }
pub fn decode_display_name(raw: &[u8]) -> Option<String> {
    decode_registration_display(raw, false).or_else(|| decode_registration_display(raw, true))
}

fn decode_registration_display(raw: &[u8], has_additional: bool) -> Option<String> {
    let input = &mut &raw[..];

    // judgements: Vec<(u32, Judgement)>
    let len = Compact::<u32>::decode(input).ok()?.0 as usize;
    for _ in 0..len {
        u32::decode(input).ok()?;
        skip_judgement(input)?;
    }

    // deposit: u128
    u128::decode(input).ok()?;

    if has_additional {
        // legacy IdentityInfo: additional: BoundedVec<(Data, Data)>
        let additional_len = Compact::<u32>::decode(input).ok()?.0 as usize;
        if additional_len > 64 {
            return None;
        }
        for _ in 0..additional_len {
            skip_data(input)?;
            skip_data(input)?;
        }
    }

    // display: Data
    decode_data_as_string(input)
}

fn decode_super_of_parent(raw: &[u8]) -> Option<[u8; 32]> {
    if raw.len() < 32 {
        return None;
    }
    let mut account = [0u8; 32];
    account.copy_from_slice(&raw[..32]);
    Some(account)
}

#[derive(Debug, Deserialize)]
struct StorageChangeSet {
    #[allow(dead_code)]
    block: String,
    changes: Vec<(String, Option<String>)>,
}

async fn batch_get_storage(
    rpc: &jsonrpsee::core::client::Client,
    keys: &[String],
) -> Result<HashMap<String, Vec<u8>>, Box<dyn std::error::Error>> {
    if keys.is_empty() {
        return Ok(HashMap::new());
    }

    const CHUNK_SIZE: usize = 500;
    let mut result_map = HashMap::with_capacity(keys.len());

    for chunk in keys.chunks(CHUNK_SIZE) {
        let response: Vec<StorageChangeSet> = rpc
            .request("state_queryStorageAt", rpc_params![chunk])
            .await?;

        for cs in &response {
            for (key, value) in &cs.changes {
                if let Some(hex_val) = value {
                    if let Ok(bytes) = hex::decode(hex_val.trim_start_matches("0x")) {
                        result_map.insert(key.clone(), bytes);
                    }
                }
            }
        }
    }

    Ok(result_map)
}

/// Resolve on-chain identity display names for a set of authorities.
///
/// 1. Maps authority discovery keys → validator stash accounts via
///    `Session::KeyOwner` on the relay chain.
/// 2. Queries `Identity::IdentityOf` on the identity chain for display names.
/// 3. Falls back to `Identity::SuperOf` → parent `IdentityOf` for sub-identities.
///
/// When `identity_url` is `None` the relay chain RPC is used for identity lookups.
pub async fn fetch_identity_names(
    relay_url: Url,
    identity_url: Option<Url>,
    authorities: &[sr25519::PublicKey],
    w: &mut impl Write,
) -> HashMap<sr25519::PublicKey, String> {
    let mut names: HashMap<sr25519::PublicKey, String> = HashMap::new();

    writeln!(w, "       Resolving authority keys → stash accounts...").ok();

    let relay_client = match client(relay_url.clone()).await {
        Ok(c) => c,
        Err(e) => {
            writeln!(w, "       Warning: relay RPC connection failed: {}", e).ok();
            return names;
        }
    };

    let key_owner_queries: Vec<(sr25519::PublicKey, String)> = authorities
        .iter()
        .map(|auth| (*auth, storage_key_session_key_owner(auth)))
        .collect();

    let hex_keys: Vec<String> = key_owner_queries.iter().map(|(_, k)| k.clone()).collect();
    let key_owner_values = match batch_get_storage(&relay_client, &hex_keys).await {
        Ok(v) => v,
        Err(e) => {
            writeln!(w, "       Warning: Session::KeyOwner query failed: {}", e).ok();
            return names;
        }
    };

    let mut auth_to_stash: HashMap<sr25519::PublicKey, [u8; 32]> = HashMap::new();
    for (auth, hex_key) in &key_owner_queries {
        if let Some(value) = key_owner_values.get(hex_key) {
            if value.len() >= 32 {
                let mut stash = [0u8; 32];
                stash.copy_from_slice(&value[..32]);
                auth_to_stash.insert(*auth, stash);
            }
        }
    }

    writeln!(
        w,
        "       Mapped {}/{} authority keys to stash accounts",
        auth_to_stash.len(),
        authorities.len()
    )
    .ok();

    if auth_to_stash.is_empty() {
        return names;
    }

    let id_url = identity_url.unwrap_or(relay_url);
    writeln!(w, "       Fetching identities from {}...", id_url).ok();

    let identity_client = match client(id_url).await {
        Ok(c) => c,
        Err(e) => {
            writeln!(
                w,
                "       Warning: identity chain RPC connection failed: {}",
                e
            )
            .ok();
            return names;
        }
    };

    let mut stash_to_auth: HashMap<[u8; 32], Vec<sr25519::PublicKey>> = HashMap::new();
    for (auth, stash) in &auth_to_stash {
        stash_to_auth.entry(*stash).or_default().push(*auth);
    }

    let unique_stashes: Vec<[u8; 32]> = stash_to_auth.keys().copied().collect();

    let identity_keys: Vec<String> = unique_stashes
        .iter()
        .map(|s| storage_key_identity_of(s))
        .collect();

    let identity_values = match batch_get_storage(&identity_client, &identity_keys).await {
        Ok(v) => v,
        Err(e) => {
            writeln!(
                w,
                "       Warning: Identity::IdentityOf query failed: {}",
                e
            )
            .ok();
            return names;
        }
    };

    let mut missing_stashes: Vec<[u8; 32]> = Vec::new();
    for (stash, hex_key) in unique_stashes.iter().zip(identity_keys.iter()) {
        if let Some(value) = identity_values.get(hex_key) {
            if let Some(display) = decode_display_name(value) {
                if let Some(auths) = stash_to_auth.get(stash) {
                    for auth in auths {
                        names.insert(*auth, display.clone());
                    }
                }
                continue;
            }
        }
        missing_stashes.push(*stash);
    }

    if !missing_stashes.is_empty() {
        let super_keys: Vec<String> = missing_stashes
            .iter()
            .map(|s| storage_key_super_of(s))
            .collect();

        if let Ok(super_values) = batch_get_storage(&identity_client, &super_keys).await {
            let mut parent_to_children: HashMap<[u8; 32], Vec<([u8; 32], Option<String>)>> =
                HashMap::new();
            for (stash, hex_key) in missing_stashes.iter().zip(super_keys.iter()) {
                if let Some(value) = super_values.get(hex_key) {
                    if let Some(parent) = decode_super_of_parent(value) {
                        let sub_name = if value.len() > 32 {
                            decode_data_as_string(&mut &value[32..])
                        } else {
                            None
                        };
                        parent_to_children
                            .entry(parent)
                            .or_default()
                            .push((*stash, sub_name));
                    }
                }
            }

            if !parent_to_children.is_empty() {
                let parent_accounts: Vec<[u8; 32]> = parent_to_children.keys().copied().collect();
                let parent_id_keys: Vec<String> = parent_accounts
                    .iter()
                    .map(|a| storage_key_identity_of(a))
                    .collect();

                if let Ok(parent_values) =
                    batch_get_storage(&identity_client, &parent_id_keys).await
                {
                    for (parent, hex_key) in parent_accounts.iter().zip(parent_id_keys.iter()) {
                        if let Some(value) = parent_values.get(hex_key) {
                            if let Some(display) = decode_display_name(value) {
                                for (child, sub_name) in
                                    parent_to_children.get(parent).into_iter().flatten()
                                {
                                    let name = match sub_name {
                                        Some(sub) => format!("{}/{}", display, sub),
                                        None => display.clone(),
                                    };
                                    if let Some(auths) = stash_to_auth.get(child) {
                                        for auth in auths {
                                            names.insert(*auth, name.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    writeln!(
        w,
        "       Resolved {}/{} identities",
        names.len(),
        authorities.len()
    )
    .ok();

    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn twox_128_session_matches_substrate() {
        assert_eq!(
            hex::encode(twox_128(b"Session")),
            "cec5070d609dd3497f72bde07fc96ba0"
        );
    }

    #[test]
    fn decode_simple_identity_info() {
        // Registration with no judgements, deposit=0x77fa6aa0, simple IdentityInfo (no additional),
        // display = Raw10("openbitlab")
        let raw =
            hex::decode("00a06afa770000000000000000000000000b6f70656e6269746c616200000000000000")
                .unwrap();
        assert_eq!(decode_display_name(&raw).as_deref(), Some("openbitlab"));
    }

    #[test]
    fn decode_legacy_identity_info_with_additional() {
        // Registration with no judgements, deposit=1 (u128), legacy IdentityInfo:
        //   additional = 0 entries, display = Raw5("Alice")
        let mut raw = Vec::new();
        raw.push(0x00); // judgements: compact(0)
        raw.extend_from_slice(&1u128.to_le_bytes()); // deposit
        raw.push(0x00); // additional: compact(0)
        raw.push(0x06); // display: variant 6 = Raw5
        raw.extend_from_slice(b"Alice");
        assert_eq!(decode_display_name(&raw).as_deref(), Some("Alice"));
    }

    #[test]
    fn decode_display_none() {
        // Registration with deposit=0, display = Data::None
        let mut raw = Vec::new();
        raw.push(0x00); // judgements: compact(0)
        raw.extend_from_slice(&0u128.to_le_bytes()); // deposit
        raw.push(0x00); // display: Data::None
        assert_eq!(decode_display_name(&raw), None);
    }
}
