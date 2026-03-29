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

## Available proofs

Each proof type has its own README with detailed usage and public output documentation.

### General (any atproto lexicon)

| Proof | Description | Docs |
|---|---|---|
| [record-authorship](proofs/record-authorship/) | DID authored a record with a specific content hash | [README](proofs/record-authorship/README.md) |
| [selective-disclosure](proofs/selective-disclosure/) | Specific record fields have specific values | [README](proofs/selective-disclosure/README.md) |
| [record-count](proofs/record-count/) | DID has at least N records in a collection | [README](proofs/record-count/README.md) |

### Bluesky posts (`app.bsky.feed.post`)

| Proof | Description | Docs |
|---|---|---|
| [post-contains](proofs/post-contains/) | Post text contains a given string | [README](proofs/post-contains/README.md) |
| [post-timestamp](proofs/post-timestamp/) | Post was created before or after a timestamp | [README](proofs/post-timestamp/README.md) |
| [post-reply-to](proofs/post-reply-to/) | Post is a reply to a specific parent | [README](proofs/post-reply-to/README.md) |
| [post-mention](proofs/post-mention/) | Post mentions a specific DID | [README](proofs/post-mention/README.md) |

### Bluesky social graph

| Proof | Description | Docs |
|---|---|---|
| [follows](proofs/follows/) | DID follows another DID | [README](proofs/follows/README.md) |
| [blocked](proofs/blocked/) | DID blocked another DID | [README](proofs/blocked/README.md) |
| [liked](proofs/liked/) | DID liked a specific post | [README](proofs/liked/README.md) |
| [reposted](proofs/reposted/) | DID reposted a specific post | [README](proofs/reposted/README.md) |
| [list-member](proofs/list-member/) | DID added someone to a specific list | [README](proofs/list-member/README.md) |
| [mutual-follow](proofs/mutual-follow/) | Two DIDs follow each other | [README](proofs/mutual-follow/README.md) |
| [not-following](proofs/not-following/) | DID does NOT follow a target DID | [README](proofs/not-following/README.md) |

### Bluesky profile (`app.bsky.actor.profile`)

| Proof | Description | Docs |
|---|---|---|
| [profile-field](proofs/profile-field/) | Profile field contains a string | [README](proofs/profile-field/README.md) |

### Quick start

```sh
# Execute any proof (test mode, no ZK proof generated)
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

The PDS endpoint is auto-resolved from the DID document. Use `--pds <url>` to override. All proofs follow this pattern — a valid proof is the assertion (the guest program aborts if the predicate is not satisfied).

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
