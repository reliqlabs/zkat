#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;

use blocked_lib::{ProofInput, ProofOutput};
use zkat_core::{hash_pubkey, parse_unsigned_commit, verify_mst_path, verify_signature, records::Block};

pub fn main() {
    let input: ProofInput = sp1_zkvm::io::read();

    let commit = parse_unsigned_commit(&input.unsigned_commit);
    assert_eq!(commit.did, input.did, "DID mismatch");
    assert_eq!(commit.version, 3, "only commit v3 supported");

    verify_signature(&input.pubkey, &input.key_type, &input.unsigned_commit, &input.signature);
    verify_mst_path(&commit.data, &input.mst_nodes, &input.record, &input.record_key);

    let block: Block = serde_ipld_dagcbor::from_slice(&input.record).expect("invalid block record");
    assert_eq!(block.subject, input.subject_did, "block subject mismatch");

    sp1_zkvm::io::commit(&ProofOutput {
        did: input.did,
        subject_did: input.subject_did,
        pubkey_hash: hash_pubkey(&input.pubkey),
        commit_rev: commit.rev,
    });
}
