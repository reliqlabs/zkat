# post-authorship

Prove that an AT Protocol account authored a post with a specific content hash, without revealing the post content.

The verifier already has the post content (obtained separately). This proof binds that content to the DID's signed repository, establishing authorship.

## Public output

| Field | Description |
|---|---|
| `did` | The author's DID |
| `record_hash` | SHA-256 hash of the post record |
| `pubkey_hash` | SHA-256 of the signing public key |
| `commit_rev` | Commit revision |

## Usage

```sh
cargo run -p post-authorship-script --release -- \
  --did did:plc:author \
  --rkey 3abc123def
```
