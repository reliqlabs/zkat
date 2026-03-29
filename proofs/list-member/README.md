# list-member

Prove that an AT Protocol account added a specific DID to a specific list.

## Public output

| Field | Description |
|---|---|
| `did` | The list owner's DID |
| `subject_did` | The DID that was added to the list |
| `list_uri` | AT URI of the list |
| `pubkey_hash` | SHA-256 of the signing public key |
| `commit_rev` | Commit revision |

## Usage

```sh
cargo run -p list-member-script --release -- \
  --did did:plc:list-owner \
  --rkey <rkey> \
  --subject did:plc:member \
  --list at://did:plc:list-owner/app.bsky.graph.list/abc123
```
