#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;

use alloc::string::String;
use alloc::collections::BTreeMap;
use ipld_core::ipld::Ipld;
use post_reply_to_lib::{ProofInput, ProofOutput};
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
        serde_ipld_dagcbor::from_slice(&input.record).expect("invalid post record");
    let reply = match record.get("reply").expect("no reply field") {
        Ipld::Map(m) => m,
        _ => panic!("reply is not a map"),
    };
    let parent = match reply.get("parent").expect("no parent in reply") {
        Ipld::Map(m) => m,
        _ => panic!("parent is not a map"),
    };
    let uri = match parent.get("uri").expect("no uri in parent") {
        Ipld::String(s) => s.as_str(),
        _ => panic!("uri is not a string"),
    };
    assert_eq!(uri, input.parent_uri, "reply parent URI mismatch");

    sp1_zkvm::io::commit(&ProofOutput {
        did: input.did,
        parent_uri: input.parent_uri,
        pubkey_hash: hash_pubkey(&input.pubkey),
        commit_rev: commit.rev,
    });
}
