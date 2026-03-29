#![no_std]
extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use zkat_core::KeyType;

/// Witness data for one direction of a follow relationship.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FollowWitness {
    pub did: String,
    pub pubkey: Vec<u8>,
    pub key_type: KeyType,
    pub unsigned_commit: Vec<u8>,
    pub signature: Vec<u8>,
    pub mst_nodes: Vec<Vec<u8>>,
    pub record: Vec<u8>,
    pub record_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofInput {
    /// A follows B
    pub a_follows_b: FollowWitness,
    /// B follows A
    pub b_follows_a: FollowWitness,
    pub did_a: String,
    pub did_b: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofOutput {
    pub did_a: String,
    pub did_b: String,
    pub pubkey_hash_a: [u8; 32],
    pub pubkey_hash_b: [u8; 32],
    pub commit_rev_a: String,
    pub commit_rev_b: String,
}
