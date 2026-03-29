# zkat

Zero-knowledge proofs over [AT Protocol](https://atproto.com/) records.

zkat enables cryptographic verification of atproto repository data without revealing the full repository state. Using [SP1](https://docs.succinct.xyz/) (a RISC-V zkVM), it generates succinct proofs that a record exists in a user's signed Merkle Search Tree — verifiable on-chain or off-chain with constant-size proofs.

## How it works

Every AT Protocol account maintains a signed repository: a Merkle Search Tree (MST) of records, committed with an ECDSA signature over the tree root. zkat exploits this structure to produce proofs of the form:

> "The account identified by DID `X` has a record at path `collection/rkey` whose content satisfies predicate `P`, as of commit revision `R`."

The proof verifies inside the ZK circuit:

1. **Commit signature** — ECDSA (secp256k1 or P-256) over the unsigned commit bytes
2. **MST hash chain** — SHA-256 content addressing from the commit root through each intermediate node to the target record
3. **Record inclusion** — the leaf MST entry's key and value CID match the target
4. **Application predicate** — proof-specific logic over the record content (e.g., text search, field matching)

The verifier receives only the public output (DID, predicate result, pubkey hash, commit revision) and a ~260-byte Groth16 proof. All record content, MST structure, and signature data remain private.

## Project structure

```
zkat/
├── crates/
│   ├── core/           # no_std: atproto verification primitives (SP1 guest)
│   └── host/           # std: DID resolution, PDS fetching, CAR parsing
├── proofs/
│   └── post-contains/  # prove a DID posted text containing a given string
│       ├── lib/        # proof-specific types (shared between guest and host)
│       ├── program/    # SP1 guest program
│       └── script/     # host binary (fetches data, generates proofs)
```

**`crates/core`** — Shared `no_std` library used by all guest programs. Provides `verify_signature()`, `verify_mst_path()`, and atproto DAG-CBOR type definitions. All cryptographic operations use SP1 precompiles (SHA-256, secp256k1, P-256) for efficient proving.

**`crates/host`** — Shared library for host-side operations: resolving DIDs via the PLC directory, fetching record proofs from a PDS as CAR files, parsing the CAR into content-addressed blocks, and extracting the MST inclusion path.

**`proofs/*`** — Each subdirectory is a self-contained proof type with its own guest program, host binary, and types. Adding a new proof requires defining the input/output types, writing a guest that calls `zkat_core::verify_*` with proof-specific record logic, and a thin host CLI.

## Prerequisites

- [Rust](https://rustup.rs/) (nightly toolchain)
- [SP1 toolchain](https://docs.succinct.xyz/docs/sp1/getting-started/install)

```sh
# Install SP1
curl -L https://sp1up.succinct.xyz | bash
sp1up
```

## Usage

### post-contains

Prove that a Bluesky account posted text containing a specific string.

```sh
# Execute (test mode, no ZK proof generated)
cargo run -p post-contains-script --release -- \
  --did did:plc:example \
  --rkey 3abc123def \
  --search "search term"

# Generate and verify a ZK proof
cargo run -p post-contains-script --release -- \
  --mode prove \
  --did did:plc:example \
  --rkey 3abc123def \
  --search "search term"
```

The PDS endpoint is auto-resolved from the DID document. Use `--pds <url>` to override.

### Public output

The proof commits the following values, visible to any verifier:

| Field | Description |
|---|---|
| `did` | The account's decentralized identifier |
| `search_string` | The string that was searched for |
| `pubkey_hash` | SHA-256 of the signing public key (verifier checks against DID resolution) |
| `commit_rev` | Commit revision TID (verifier can check recency) |

A valid proof is itself the assertion that the post was found — the guest program aborts if the record does not contain the search string, making proof generation impossible.

## Adding a new proof type

1. Create `proofs/<name>/{lib,program,script}` following the `post-contains` structure
2. Define `ProofInput` and `ProofOutput` in `lib/` (`no_std` compatible)
3. Write the guest program in `program/` — call `zkat_core::verify_signature()` and `zkat_core::verify_mst_path()`, then add record-specific logic
4. Write the host binary in `script/` — use `zkat_host` for data fetching, construct the `ProofInput`, and drive SP1
5. Add the three crates to the workspace `members` in the root `Cargo.toml`

## Architecture notes

- **SP1 precompiles** — SHA-256, secp256k1, and P-256 operations are accelerated via patched crates (`[patch.crates-io]` in the workspace root). The guest code uses standard Rust APIs (`sha2`, `k256`, `p256`); the patches transparently redirect to zkVM syscalls.
- **Unsigned commit bytes** — Following the approach used by [skeet-gateway](https://github.com/edmundedgar/skeet-gateway), the host strips the `sig` field from the signed commit and passes the raw unsigned bytes to the guest. This avoids re-serialization inside the circuit and eliminates DAG-CBOR encoding ambiguity.
- **Groth16 wrapping** — SP1 supports wrapping STARK proofs in a Groth16 proof for on-chain verification (~260 bytes, ~270k gas on Ethereum). This is available via `--mode prove` with the appropriate SP1 prover configuration.

## License

MIT
