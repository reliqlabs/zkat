# follows

Prove that an AT Protocol account follows another account, without revealing the rest of their follow list.

## Public output

| Field | Description |
|---|---|
| `did` | The follower's DID |
| `subject_did` | The DID being followed |
| `pubkey_hash` | SHA-256 of the signing public key |
| `commit_rev` | Commit revision |

A valid proof is the assertion — proof generation fails if the follow record does not exist or does not match the subject DID.

## Usage

```sh
cargo run -p follows-script --release -- \
  --did did:plc:follower \
  --rkey <rkey> \
  --subject did:plc:followed
```
