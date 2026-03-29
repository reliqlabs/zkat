#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;

use post_mention_lib::{ProofInput, ProofOutput};
use zkat_core::{hash_pubkey, parse_unsigned_commit, verify_mst_path, verify_signature, records::Post};

pub fn main() {
    let input: ProofInput = sp1_zkvm::io::read();

    let commit = parse_unsigned_commit(&input.unsigned_commit);
    assert_eq!(commit.did, input.did, "DID mismatch");
    assert_eq!(commit.version, 3, "only commit v3 supported");

    verify_signature(&input.pubkey, &input.key_type, &input.unsigned_commit, &input.signature);
    verify_mst_path(&commit.data, &input.mst_nodes, &input.record, &input.record_key);

    let post: Post = serde_ipld_dagcbor::from_slice(&input.record).expect("invalid post record");

    let facets = post.facets.expect("post has no facets");
    let mut found_mention = false;
    for facet in &facets {
        for feature in &facet.features {
            if feature.feature_type == "app.bsky.richtext.facet#mention" {
                if let Some(ref did) = feature.did {
                    if did == &input.mentioned_did {
                        found_mention = true;
                    }
                }
            }
        }
    }
    assert!(found_mention, "mentioned DID not found in post facets");

    sp1_zkvm::io::commit(&ProofOutput {
        did: input.did,
        mentioned_did: input.mentioned_did,
        pubkey_hash: hash_pubkey(&input.pubkey),
        commit_rev: commit.rev,
    });
}
