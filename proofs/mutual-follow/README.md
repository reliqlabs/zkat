# mutual-follow

Prove that two AT Protocol accounts follow each other, in a single proof.

Composes two follow inclusion proofs — one from each account's repository. Both signatures and MST paths are verified inside the same ZK circuit.

## Public output

| Field | Description |
|---|---|
| `did_a` | First account's DID |
| `did_b` | Second account's DID |
| `pubkey_hash_a` | SHA-256 of A's signing public key |
| `pubkey_hash_b` | SHA-256 of B's signing public key |
| `commit_rev_a` | A's commit revision |
| `commit_rev_b` | B's commit revision |

## Usage

```sh
cargo run -p mutual-follow-script --release -- \
  --did-a did:plc:alice \
  --rkey-a <rkey of alice's follow of bob> \
  --did-b did:plc:bob \
  --rkey-b <rkey of bob's follow of alice>
```
