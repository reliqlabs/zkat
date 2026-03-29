# liked

Prove that an AT Protocol account liked a specific post, without revealing their like history.

## Public output

| Field | Description |
|---|---|
| `did` | The liker's DID |
| `subject_uri` | AT URI of the liked post |
| `pubkey_hash` | SHA-256 of the signing public key |
| `commit_rev` | Commit revision |

## Usage

```sh
cargo run -p liked-script --release -- \
  --did did:plc:liker \
  --rkey <rkey> \
  --subject at://did:plc:author/app.bsky.feed.post/abc123
```
