# record-authorship

Prove that an AT Protocol account authored a record with a specific content hash, without revealing the record content. Works with any collection and lexicon.

The verifier already has the record content (obtained separately). This proof binds that content to the DID's signed repository, establishing authorship.

## Public output

| Field | Description |
|---|---|
| `did` | The author's DID |
| `record_key` | The full record key (collection/rkey) |
| `record_hash` | SHA-256 hash of the record |
| `pubkey_hash` | SHA-256 of the signing public key |
| `commit_rev` | Commit revision |

## Usage

```sh
cargo run -p record-authorship-script --release -- \
  --did did:plc:author \
  --collection app.bsky.feed.post \
  --rkey 3abc123def
```
