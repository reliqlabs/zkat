# not-following

Prove that an AT Protocol account does NOT follow a specific DID.

This is a proof of absence. The prover fetches all follow records from the account, verifies each one is in the signed MST, and asserts that none have the target DID as their subject. The public output includes the total follow count as a completeness indicator.

## Limitations

The current implementation fetches and verifies every follow record individually. For accounts with many follows (thousands), this results in a large witness and long proving time. A future version will use MST subtree proofs for better scaling.

The `expected_count` field in the proof output indicates how many follow records were checked. A verifier should cross-reference this with the account's known follow count.

## Public output

| Field | Description |
|---|---|
| `did` | The account's DID |
| `target_did` | The DID that is NOT followed |
| `follow_count` | Number of follow records checked |
| `pubkey_hash` | SHA-256 of the signing public key |
| `commit_rev` | Commit revision |

## Usage

```sh
cargo run -p not-following-script --release -- \
  --did did:plc:account \
  --target did:plc:not-followed
```

Note: this fetches all follow records from the PDS. For accounts with many follows, the initial data fetch may take some time.

## TODO

- [ ] End-to-end test against a live account
- [ ] Handle commit rotation between individual `getRecord` calls (all CAR fetches must reference the same commit)
- [ ] MST subtree proof for efficient verification without per-record CAR fetches
- [ ] Benchmark cycle count scaling with follow count
