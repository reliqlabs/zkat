#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;

use not_following_lib::{ProofInput, ProofOutput};
use zkat_core::{hash_pubkey, parse_unsigned_commit, verify_mst_path, verify_signature, records::Follow};

pub fn main() {
    let input: ProofInput = sp1_zkvm::io::read();

    let commit = parse_unsigned_commit(&input.unsigned_commit);
    assert_eq!(commit.did, input.did, "DID mismatch");
    assert_eq!(commit.version, 3, "only commit v3 supported");

    verify_signature(&input.pubkey, &input.key_type, &input.unsigned_commit, &input.signature);

    // Verify each follow record is in the MST and none match the target
    let mut count: u64 = 0;
    for entry in &input.follows {
        verify_mst_path(&commit.data, &entry.mst_nodes, &entry.record, &entry.record_key);

        let follow: Follow = serde_ipld_dagcbor::from_slice(&entry.record).expect("invalid follow record");
        assert_ne!(follow.subject, input.target_did, "found follow of target DID — cannot prove not-following");
        count += 1;
    }
    assert_eq!(count, input.expected_count, "follow count mismatch — incomplete witness");

    sp1_zkvm::io::commit(&ProofOutput {
        did: input.did,
        target_did: input.target_did,
        follow_count: count,
        pubkey_hash: hash_pubkey(&input.pubkey),
        commit_rev: commit.rev,
    });
}
