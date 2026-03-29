#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;

use alloc::string::String;
use alloc::collections::BTreeMap;
use ipld_core::ipld::Ipld;
use liked_lib::{ProofInput, ProofOutput};
use zkat_core::{hash_pubkey, parse_unsigned_commit, verify_mst_path, verify_signature};

pub fn main() {
    let input: ProofInput = sp1_zkvm::io::read();

    let commit = parse_unsigned_commit(&input.unsigned_commit);
    assert_eq!(commit.did, input.did, "DID mismatch");
    assert_eq!(commit.version, 3, "only commit v3 supported");

    verify_signature(&input.pubkey, &input.key_type, &input.unsigned_commit, &input.signature);
    verify_mst_path(&commit.data, &input.mst_nodes, &input.record, &input.record_key);

    // Parse generically to avoid DAG-CBOR struct deserialization issues
    let record: BTreeMap<String, Ipld> =
        serde_ipld_dagcbor::from_slice(&input.record).expect("invalid like record");
    let subject = match record.get("subject").expect("no subject field") {
        Ipld::Map(m) => m,
        _ => panic!("subject is not a map"),
    };
    let uri = match subject.get("uri").expect("no uri in subject") {
        Ipld::String(s) => s.as_str(),
        _ => panic!("uri is not a string"),
    };
    assert_eq!(uri, input.subject_uri, "like subject URI mismatch");

    sp1_zkvm::io::commit(&ProofOutput {
        did: input.did,
        subject_uri: input.subject_uri,
        pubkey_hash: hash_pubkey(&input.pubkey),
        commit_rev: commit.rev,
    });
}
