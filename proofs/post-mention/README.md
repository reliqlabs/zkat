# post-mention

Prove that an AT Protocol account mentioned another DID in a post, without revealing the post content.

Mentions are extracted from the post's richtext facets (`app.bsky.richtext.facet#mention`).

## Public output

| Field | Description |
|---|---|
| `did` | The post author's DID |
| `mentioned_did` | The DID that was mentioned |
| `pubkey_hash` | SHA-256 of the signing public key |
| `commit_rev` | Commit revision |

## Usage

```sh
cargo run -p post-mention-script --release -- \
  --did did:plc:author \
  --rkey 3abc123def \
  --mentioned did:plc:target
```
