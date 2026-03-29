#![no_std]
extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use zkat_core::KeyType;

/// A single follow record with its MST inclusion proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FollowEntry {
    pub mst_nodes: Vec<Vec<u8>>,
    pub record: Vec<u8>,
    pub record_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofInput {
    pub did: String,
    pub pubkey: Vec<u8>,
    pub key_type: KeyType,
    pub unsigned_commit: Vec<u8>,
    pub signature: Vec<u8>,
    /// All follow records in the account, each with its MST path.
    pub follows: Vec<FollowEntry>,
    /// The DID to prove is NOT followed.
    pub target_did: String,
    /// Total number of follow records in the collection (for completeness check).
    pub expected_count: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofOutput {
    pub did: String,
    pub target_did: String,
    pub follow_count: u64,
    pub pubkey_hash: [u8; 32],
    pub commit_rev: String,
}
