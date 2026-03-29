#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;

use profile_field_lib::{ProofInput, ProofOutput, ProfileFieldTarget};
use zkat_core::{hash_pubkey, parse_unsigned_commit, verify_mst_path, verify_signature, records::Profile};

pub fn main() {
    let input: ProofInput = sp1_zkvm::io::read();

    let commit = parse_unsigned_commit(&input.unsigned_commit);
    assert_eq!(commit.did, input.did, "DID mismatch");
    assert_eq!(commit.version, 3, "only commit v3 supported");

    verify_signature(&input.pubkey, &input.key_type, &input.unsigned_commit, &input.signature);
    verify_mst_path(&commit.data, &input.mst_nodes, &input.record, &input.record_key);

    let profile: Profile = serde_ipld_dagcbor::from_slice(&input.record).expect("invalid profile record");

    let field_value = match input.field {
        ProfileFieldTarget::DisplayName => profile.display_name.expect("no display name"),
        ProfileFieldTarget::Description => profile.description.expect("no description"),
    };
    assert!(field_value.contains(input.search_string.as_str()), "field does not contain search string");

    sp1_zkvm::io::commit(&ProofOutput {
        did: input.did,
        field: input.field,
        search_string: input.search_string,
        pubkey_hash: hash_pubkey(&input.pubkey),
        commit_rev: commit.rev,
    });
}
