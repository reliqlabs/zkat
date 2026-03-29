#![no_std]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use ipld_core::cid::Cid;
use sha2::{Digest, Sha256};

// Re-export for convenience in guest programs.
pub use ipld_core::cid;
pub use sha2;

// -- Key types --

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum KeyType {
    P256,
    Secp256k1,
}

// -- atproto DAG-CBOR types --

/// Unsigned commit v3 fields.
#[derive(serde::Deserialize)]
pub struct CommitData {
    pub did: String,
    pub rev: String,
    pub data: Cid,
    pub prev: Option<Cid>,
    pub version: u64,
}

#[derive(serde::Deserialize)]
pub struct MstNode {
    #[serde(rename = "l")]
    pub left: Option<Cid>,
    #[serde(rename = "e")]
    pub entries: Vec<TreeEntry>,
}

#[derive(serde::Deserialize)]
pub struct TreeEntry {
    #[serde(rename = "p")]
    pub prefix_len: u32,
    #[serde(rename = "k", with = "serde_bytes")]
    pub key_suffix: Vec<u8>,
    #[serde(rename = "v")]
    pub value: Cid,
    #[serde(rename = "t")]
    pub tree: Option<Cid>,
}

// -- Commit parsing --

/// Parse unsigned commit bytes (sig already stripped) into structured data.
pub fn parse_unsigned_commit(bytes: &[u8]) -> CommitData {
    serde_ipld_dagcbor::from_slice(bytes).expect("invalid unsigned commit cbor")
}

// -- Signature verification --

/// Verify an ECDSA signature over `message` using the given public key.
/// Panics on failure (appropriate for ZK guest — invalid witness = unprovable).
pub fn verify_signature(pubkey: &[u8], key_type: &KeyType, message: &[u8], sig_bytes: &[u8]) {
    match key_type {
        KeyType::Secp256k1 => {
            use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let vk = VerifyingKey::from_sec1_bytes(pubkey).expect("invalid secp256k1 pubkey");
            let sig = Signature::from_slice(sig_bytes).expect("invalid secp256k1 signature");
            vk.verify(message, &sig)
                .expect("secp256k1 signature verification failed");
        }
        KeyType::P256 => {
            use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let vk = VerifyingKey::from_sec1_bytes(pubkey).expect("invalid p256 pubkey");
            let sig = Signature::from_slice(sig_bytes).expect("invalid p256 signature");
            vk.verify(message, &sig)
                .expect("p256 signature verification failed");
        }
    }
}

// -- MST path verification --

/// Verify a Merkle Search Tree inclusion proof.
///
/// Checks that:
/// 1. `sha256(mst_nodes[0]) == root_cid` (binds to the signed commit)
/// 2. Each node links to the next via a subtree pointer
/// 3. The last node contains `record_key` pointing to `sha256(record)`
///
/// Panics on any verification failure.
pub fn verify_mst_path(root_cid: &Cid, mst_nodes: &[Vec<u8>], record: &[u8], record_key: &str) {
    assert!(!mst_nodes.is_empty(), "empty MST path");

    let root_hash: [u8; 32] = Sha256::digest(&mst_nodes[0]).into();
    assert_eq!(
        &root_hash,
        root_cid.hash().digest(),
        "root MST node hash does not match commit.data"
    );

    let mut nodes: Vec<MstNode> = Vec::with_capacity(mst_nodes.len());
    let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(mst_nodes.len());
    for node_bytes in mst_nodes {
        nodes.push(serde_ipld_dagcbor::from_slice(node_bytes).expect("invalid MST node cbor"));
        hashes.push(Sha256::digest(node_bytes).into());
    }

    for i in 0..nodes.len() - 1 {
        assert!(
            node_has_subtree_hash(&nodes[i], &hashes[i + 1]),
            "MST chain broken at level {}",
            i
        );
    }

    let record_hash: [u8; 32] = Sha256::digest(record).into();
    let last = &nodes[nodes.len() - 1];
    let mut prev_key: Vec<u8> = Vec::new();
    let mut found = false;

    for entry in &last.entries {
        let key = reconstruct_key(&prev_key, entry.prefix_len as usize, &entry.key_suffix);
        if key.as_slice() == record_key.as_bytes() {
            assert_eq!(
                entry.value.hash().digest(),
                &record_hash,
                "record CID hash mismatch"
            );
            found = true;
            break;
        }
        prev_key = key;
    }
    assert!(found, "record key not found in leaf MST node");
}

/// Compute SHA-256 hash of a public key (for binding in proof output).
pub fn hash_pubkey(pubkey: &[u8]) -> [u8; 32] {
    Sha256::digest(pubkey).into()
}

fn node_has_subtree_hash(node: &MstNode, target: &[u8; 32]) -> bool {
    if let Some(ref left) = node.left {
        if left.hash().digest() == target {
            return true;
        }
    }
    for entry in &node.entries {
        if let Some(ref tree) = entry.tree {
            if tree.hash().digest() == target {
                return true;
            }
        }
    }
    false
}

fn reconstruct_key(prev_key: &[u8], prefix_len: usize, suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix_len + suffix.len());
    if prefix_len > 0 {
        key.extend_from_slice(&prev_key[..prefix_len]);
    }
    key.extend_from_slice(suffix);
    key
}

// -- Bluesky record types (DAG-CBOR deserialization for guest programs) --

/// Bluesky record types.
///
/// All types use `#[serde(default)]` on optional fields and include
/// `$type` to handle the atproto type discriminator in DAG-CBOR.
pub mod records {
    use alloc::string::String;
    use alloc::vec::Vec;

    /// `app.bsky.feed.post`
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Post {
        #[serde(rename = "$type", default)]
        pub _type: Option<String>,
        pub text: String,
        pub created_at: String,
        /// Reply ref uses Ipld because StrongRef contains CID (CBOR tag 42)
        /// which serde_ipld_dagcbor can't deserialize in struct mode.
        #[serde(default)]
        pub reply: Option<ipld_core::ipld::Ipld>,
        #[serde(default)]
        pub facets: Option<Vec<Facet>>,
        #[serde(default)]
        pub langs: Option<Vec<String>>,
        #[serde(default)]
        pub embed: Option<ipld_core::ipld::Ipld>,
        #[serde(default)]
        pub labels: Option<ipld_core::ipld::Ipld>,
        #[serde(default)]
        pub tags: Option<Vec<String>>,
    }

    #[derive(serde::Deserialize)]
    pub struct Facet {
        #[serde(rename = "$type", default)]
        pub _type: Option<String>,
        pub index: ByteSlice,
        pub features: Vec<FacetFeature>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ByteSlice {
        pub byte_start: u64,
        pub byte_end: u64,
    }

    #[derive(serde::Deserialize)]
    pub struct FacetFeature {
        #[serde(rename = "$type")]
        pub feature_type: String,
        #[serde(default)]
        pub did: Option<String>,
        #[serde(default)]
        pub uri: Option<String>,
        #[serde(default)]
        pub tag: Option<String>,
    }

    /// `app.bsky.graph.follow`
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Follow {
        #[serde(rename = "$type", default)]
        pub _type: Option<String>,
        pub subject: String,
        pub created_at: String,
    }

    // Note: Like and Repost records contain CID fields in `subject: StrongRef`
    // which serde_ipld_dagcbor cannot deserialize in struct mode (no_std).
    // Guest programs for liked/reposted use generic Ipld deserialization instead.

    /// `app.bsky.graph.block`
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Block {
        #[serde(rename = "$type", default)]
        pub _type: Option<String>,
        pub subject: String,
        pub created_at: String,
    }

    /// `app.bsky.graph.listitem`
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ListItem {
        #[serde(rename = "$type", default)]
        pub _type: Option<String>,
        pub subject: String,
        pub list: String,
        pub created_at: String,
    }

    /// `app.bsky.actor.profile` (rkey is always "self")
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Profile {
        #[serde(rename = "$type", default)]
        pub _type: Option<String>,
        #[serde(default)]
        pub display_name: Option<String>,
        #[serde(default)]
        pub description: Option<String>,
        #[serde(default)]
        pub avatar: Option<ipld_core::ipld::Ipld>,
        #[serde(default)]
        pub banner: Option<ipld_core::ipld::Ipld>,
        #[serde(default)]
        pub labels: Option<ipld_core::ipld::Ipld>,
        #[serde(default)]
        pub pronouns: Option<String>,
    }
}
