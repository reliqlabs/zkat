# blocked

Prove that an AT Protocol account blocked another account, without revealing the full block list.

Useful in moderation disputes where a block action needs to be demonstrated without exposing all other blocks.

## Public output

| Field | Description |
|---|---|
| `did` | The blocker's DID |
| `subject_did` | The blocked DID |
| `pubkey_hash` | SHA-256 of the signing public key |
| `commit_rev` | Commit revision |

## Usage

```sh
cargo run -p blocked-script --release -- \
  --did did:plc:blocker \
  --rkey <rkey> \
  --subject did:plc:blocked
```
