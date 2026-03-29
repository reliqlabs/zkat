# reposted

Prove that an AT Protocol account reposted a specific post, without revealing their repost history.

## Public output

| Field | Description |
|---|---|
| `did` | The reposter's DID |
| `subject_uri` | AT URI of the reposted post |
| `pubkey_hash` | SHA-256 of the signing public key |
| `commit_rev` | Commit revision |

## Usage

```sh
cargo run -p reposted-script --release -- \
  --did did:plc:reposter \
  --rkey <rkey> \
  --subject at://did:plc:author/app.bsky.feed.post/abc123
```
