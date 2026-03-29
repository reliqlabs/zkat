#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;

use list_member_lib::{ProofInput, ProofOutput};
use zkat_core::{hash_pubkey, parse_unsigned_commit, verify_mst_path, verify_signature, records::ListItem};

pub fn main() {
    let input: ProofInput = sp1_zkvm::io::read();

    let commit = parse_unsigned_commit(&input.unsigned_commit);
    assert_eq!(commit.did, input.did, "DID mismatch");
    assert_eq!(commit.version, 3, "only commit v3 supported");

    verify_signature(&input.pubkey, &input.key_type, &input.unsigned_commit, &input.signature);
    verify_mst_path(&commit.data, &input.mst_nodes, &input.record, &input.record_key);

    let item: ListItem = serde_ipld_dagcbor::from_slice(&input.record).expect("invalid listitem record");
    assert_eq!(item.subject, input.subject_did, "list item subject mismatch");
    assert_eq!(item.list, input.list_uri, "list URI mismatch");

    sp1_zkvm::io::commit(&ProofOutput {
        did: input.did,
        subject_did: input.subject_did,
        list_uri: input.list_uri,
        pubkey_hash: hash_pubkey(&input.pubkey),
        commit_rev: commit.rev,
    });
}
