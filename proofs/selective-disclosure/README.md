# selective-disclosure

Prove that specific fields of an AT Protocol record have specific values, without revealing the rest of the record.

This is the most general proof type — it works with any record collection and any string/integer/boolean fields. The verifier learns only the asserted field values; all other record content remains private.

## Public output

| Field | Description |
|---|---|
| `did` | The account's DID |
| `record_key` | The full record key (collection/rkey) |
| `assertions` | List of (field, value) pairs that were verified |
| `pubkey_hash` | SHA-256 of the signing public key |
| `commit_rev` | Commit revision |

## Usage

```sh
cargo run -p selective-disclosure-script --release -- \
  --did did:plc:example \
  --collection app.bsky.feed.post \
  --rkey 3abc123def \
  --assert "text=hello world" \
  --assert "createdAt=2025-01-01T00:00:00Z"
```

Multiple `--assert` flags can be provided. Each must be in `field=value` format. The proof fails if any assertion does not match.
