#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;
use alloc::string::{String, ToString};
use core::fmt::Write;

use ipld_core::ipld::Ipld;
use selective_disclosure_lib::{ProofInput, ProofOutput};
use zkat_core::{hash_pubkey, parse_unsigned_commit, verify_mst_path, verify_signature};

pub fn main() {
    let input: ProofInput = sp1_zkvm::io::read();

    let commit = parse_unsigned_commit(&input.unsigned_commit);
    assert_eq!(commit.did, input.did, "DID mismatch");
    assert_eq!(commit.version, 3, "only commit v3 supported");

    verify_signature(&input.pubkey, &input.key_type, &input.unsigned_commit, &input.signature);
    verify_mst_path(&commit.data, &input.mst_nodes, &input.record, &input.record_key);

    let record: Ipld = serde_ipld_dagcbor::from_slice(&input.record).expect("invalid record cbor");
    let map = match record {
        Ipld::Map(m) => m,
        _ => panic!("record is not a CBOR map"),
    };

    for assertion in &input.assertions {
        let value = map.get(&assertion.field)
            .unwrap_or_else(|| panic!("field '{}' not found", assertion.field));
        let value_str = ipld_to_string(value);
        assert_eq!(value_str, assertion.value, "field '{}' mismatch", assertion.field);
    }

    sp1_zkvm::io::commit(&ProofOutput {
        did: input.did,
        record_key: input.record_key,
        assertions: input.assertions,
        pubkey_hash: hash_pubkey(&input.pubkey),
        commit_rev: commit.rev,
    });
}

fn ipld_to_string(v: &Ipld) -> String {
    match v {
        Ipld::String(s) => s.clone(),
        Ipld::Integer(n) => {
            let mut buf = String::new();
            write!(buf, "{}", n).unwrap();
            buf
        }
        Ipld::Bool(b) => if *b { "true".to_string() } else { "false".to_string() },
        Ipld::Null => "null".to_string(),
        _ => panic!("unsupported value type for string conversion"),
    }
}
