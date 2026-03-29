#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;

use record_count_lib::{ProofInput, ProofOutput};
use zkat_core::{hash_pubkey, parse_unsigned_commit, verify_mst_path, verify_signature};

pub fn main() {
    let input: ProofInput = sp1_zkvm::io::read();

    let commit = parse_unsigned_commit(&input.unsigned_commit);
    assert_eq!(commit.did, input.did, "DID mismatch");
    assert_eq!(commit.version, 3, "only commit v3 supported");

    verify_signature(&input.pubkey, &input.key_type, &input.unsigned_commit, &input.signature);

    // Verify each record is in the MST and belongs to the collection
    let mut count: u64 = 0;
    let prefix = alloc::format!("{}/", input.collection);
    for entry in &input.records {
        assert!(entry.record_key.starts_with(prefix.as_str()), "record not in collection");
        verify_mst_path(&commit.data, &entry.mst_nodes, &entry.record, &entry.record_key);
        count += 1;
    }
    assert!(count >= input.min_count, "count {} < minimum {}", count, input.min_count);

    sp1_zkvm::io::commit(&ProofOutput {
        did: input.did,
        collection: input.collection,
        count,
        min_count: input.min_count,
        pubkey_hash: hash_pubkey(&input.pubkey),
        commit_rev: commit.rev,
    });
}
