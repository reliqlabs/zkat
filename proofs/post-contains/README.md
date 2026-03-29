# post-contains

Prove that a specific AT Protocol account published a Bluesky post containing a given string, without revealing which post matched.

## Motivation

Consider a scenario where you need to demonstrate that a user said something — a compliance check, a moderation signal, a bet settlement — but you do not want to reveal the specific post, its timestamp, its record key, or any surrounding content. The verifier learns only:

- **Who**: the DID of the account
- **What**: the search string that was present in the post text

The existence of a valid proof is itself the assertion — if the post does not contain the string, proof generation fails. There is no `found` flag; a proof that verifies means the string was found.

Everything else — the post body, the record key, the MST structure, the commit signature, the signing key — remains private to the prover.

## What the proof verifies

Inside the ZK circuit:

1. The unsigned commit is signed by the provided public key (ECDSA secp256k1 or P-256)
2. The commit's `data` CID binds to the MST root via SHA-256
3. A valid hash chain connects the MST root through intermediate nodes to the leaf containing the record
4. The leaf entry's key is under `app.bsky.feed.post/` and its value CID matches `sha256(record)`
5. The record's `text` field contains the search string

## Public output

| Field | Description |
|---|---|
| `did` | Account DID |
| `search_string` | The string that was matched |
| `pubkey_hash` | SHA-256 of the signing public key |
| `commit_rev` | Commit revision (TID), usable as a freshness bound |

## What remains private

- The full post text
- The record key (which post matched)
- The MST inclusion path
- The commit signature
- The signing public key (only its hash is revealed)

## Verification

A verifier holding the proof checks:

1. The proof is valid (constant-time, ~260 bytes with Groth16 wrapping)
2. `pubkey_hash` matches the current signing key for `did` (resolved via the PLC directory)
3. `commit_rev` is recent enough for their trust model

This separates the expensive work (signature verification, Merkle traversal, string matching) from the cheap work (proof verification, DID resolution). The prover bears the cost once; any number of verifiers can check the result.

## Usage

```sh
# Execute (test mode, no proof)
cargo run -p post-contains-script --release -- \
  --did did:plc:example \
  --rkey 3abc123def \
  --search "search term"

# Generate a ZK proof
cargo run -p post-contains-script --release -- \
  --mode prove \
  --did did:plc:example \
  --rkey 3abc123def \
  --search "search term"
```

The `--rkey` identifies which post to prove over. The PDS is auto-resolved from the DID document; use `--pds <url>` to override.
