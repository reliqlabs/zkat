#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;

use post_authorship_lib::{ProofInput, ProofOutput};
use zkat_core::{hash_pubkey, parse_unsigned_commit, verify_mst_path, verify_signature};
use zkat_core::sha2::{Digest, Sha256};

pub fn main() {
    let input: ProofInput = sp1_zkvm::io::read();

    let commit = parse_unsigned_commit(&input.unsigned_commit);
    assert_eq!(commit.did, input.did, "DID mismatch");
    assert_eq!(commit.version, 3, "only commit v3 supported");

    verify_signature(&input.pubkey, &input.key_type, &input.unsigned_commit, &input.signature);
    verify_mst_path(&commit.data, &input.mst_nodes, &input.record, &input.record_key);

    let record_hash: [u8; 32] = Sha256::digest(&input.record).into();

    sp1_zkvm::io::commit(&ProofOutput {
        did: input.did,
        record_hash,
        pubkey_hash: hash_pubkey(&input.pubkey),
        commit_rev: commit.rev,
    });
}
