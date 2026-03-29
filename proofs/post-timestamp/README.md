# post-timestamp

Prove that an AT Protocol account made a post before or after a given timestamp, without revealing the post content.

Note: the `createdAt` field is self-reported by the client. This proof verifies it was committed to the signed repository, not that the timestamp is accurate.

## Public output

| Field | Description |
|---|---|
| `did` | The author's DID |
| `boundary` | The timestamp boundary (ISO 8601) |
| `before` | Whether the post was created before the boundary |
| `pubkey_hash` | SHA-256 of the signing public key |
| `commit_rev` | Commit revision |

## Usage

```sh
cargo run -p post-timestamp-script --release -- \
  --did did:plc:author \
  --rkey 3abc123def \
  --boundary "2025-01-01T00:00:00Z" \
  --before
```
