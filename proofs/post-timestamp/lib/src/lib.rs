#![no_std]
extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use zkat_core::KeyType;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofInput {
    pub did: String,
    pub pubkey: Vec<u8>,
    pub key_type: KeyType,
    pub unsigned_commit: Vec<u8>,
    pub signature: Vec<u8>,
    pub mst_nodes: Vec<Vec<u8>>,
    pub record: Vec<u8>,
    pub record_key: String,
    /// The timestamp boundary to check against (ISO 8601)
    pub boundary: String,
    /// true = prove post was created before boundary, false = after
    pub before: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofOutput {
    pub did: String,
    pub boundary: String,
    pub before: bool,
    pub pubkey_hash: [u8; 32],
    pub commit_rev: String,
}
