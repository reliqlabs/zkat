#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;

use mutual_follow_lib::{FollowWitness, ProofInput, ProofOutput};
use zkat_core::{hash_pubkey, parse_unsigned_commit, verify_mst_path, verify_signature, records::Follow};

fn verify_follow(w: &FollowWitness, expected_subject: &str) -> (alloc::string::String, [u8; 32]) {
    let commit = parse_unsigned_commit(&w.unsigned_commit);
    assert_eq!(commit.did, w.did, "DID mismatch");
    assert_eq!(commit.version, 3, "only commit v3 supported");

    verify_signature(&w.pubkey, &w.key_type, &w.unsigned_commit, &w.signature);
    verify_mst_path(&commit.data, &w.mst_nodes, &w.record, &w.record_key);

    let follow: Follow = serde_ipld_dagcbor::from_slice(&w.record).expect("invalid follow record");
    assert_eq!(follow.subject, expected_subject, "follow subject mismatch");

    (commit.rev, hash_pubkey(&w.pubkey))
}

pub fn main() {
    let input: ProofInput = sp1_zkvm::io::read();

    // Verify A follows B
    let (rev_a, pk_hash_a) = verify_follow(&input.a_follows_b, &input.did_b);
    assert_eq!(input.a_follows_b.did, input.did_a, "A DID mismatch");

    // Verify B follows A
    let (rev_b, pk_hash_b) = verify_follow(&input.b_follows_a, &input.did_a);
    assert_eq!(input.b_follows_a.did, input.did_b, "B DID mismatch");

    sp1_zkvm::io::commit(&ProofOutput {
        did_a: input.did_a,
        did_b: input.did_b,
        pubkey_hash_a: pk_hash_a,
        pubkey_hash_b: pk_hash_b,
        commit_rev_a: rev_a,
        commit_rev_b: rev_b,
    });
}
