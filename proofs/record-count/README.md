# record-count

Prove that an AT Protocol account has at least N records in a given collection, without revealing the record contents.

The prover provides N records from the collection, each with its MST inclusion proof. The circuit verifies that all N records exist in the signed repository under the specified collection.

## Public output

| Field | Description |
|---|---|
| `did` | The account's DID |
| `collection` | The collection (e.g., `app.bsky.feed.post`) |
| `count` | Number of records verified |
| `min_count` | The minimum count that was asserted |
| `pubkey_hash` | SHA-256 of the signing public key |
| `commit_rev` | Commit revision |

## Usage

```sh
cargo run -p record-count-script --release -- \
  --did did:plc:example \
  --collection app.bsky.feed.post \
  --min-count 100
```

Note: this fetches N individual record proofs from the PDS. For large N, the initial data fetch may take some time.

## TODO

- [ ] End-to-end test against a live account
- [ ] Handle commit rotation between individual `getRecord` calls (all CAR fetches must reference the same commit)
- [ ] Deduplicate shared MST nodes across record proofs to reduce witness size
- [ ] MST subtree proof for efficient counting without per-record CAR fetches
- [ ] Benchmark cycle count scaling with N
