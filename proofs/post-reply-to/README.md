# post-reply-to

Prove that an AT Protocol account replied to a specific post, without revealing the reply content.

## Public output

| Field | Description |
|---|---|
| `did` | The replier's DID |
| `parent_uri` | AT URI of the parent post |
| `pubkey_hash` | SHA-256 of the signing public key |
| `commit_rev` | Commit revision |

## Usage

```sh
cargo run -p post-reply-to-script --release -- \
  --did did:plc:replier \
  --rkey 3abc123def \
  --parent at://did:plc:author/app.bsky.feed.post/xyz789
```
