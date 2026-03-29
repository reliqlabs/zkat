# profile-field

Prove that an AT Protocol account's profile contains a specific string in the display name or description, without revealing the full profile.

## Public output

| Field | Description |
|---|---|
| `did` | The account's DID |
| `field` | Which profile field was checked (DisplayName or Description) |
| `search_string` | The string that was matched |
| `pubkey_hash` | SHA-256 of the signing public key |
| `commit_rev` | Commit revision |

## Usage

```sh
cargo run -p profile-field-script --release -- \
  --did did:plc:example \
  --field display-name \
  --search "keyword"
```
