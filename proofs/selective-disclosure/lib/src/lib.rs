#![no_std]
extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use zkat_core::KeyType;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldAssertion {
    pub field: String,
    pub value: String,
}

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
    pub assertions: Vec<FieldAssertion>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofOutput {
    pub did: String,
    pub record_key: String,
    pub assertions: Vec<FieldAssertion>,
    pub pubkey_hash: [u8; 32],
    pub commit_rev: String,
}
