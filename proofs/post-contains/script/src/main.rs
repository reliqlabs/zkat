use anyhow::{bail, Context, Result};
use clap::Parser;
use sp1_sdk::{include_elf, Elf, SP1Stdin};
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::ProvingKey;
use zkat_host::{
    extract_commit_proof_data, extract_mst_path, fetch_record_car, find_record_cid, parse_car,
    resolve_did,
};
use post_contains_lib::{ProofInput, ProofOutput};

const ELF: Elf = include_elf!("post-contains-program");

#[derive(Parser)]
#[command(name = "post-contains", about = "Prove a DID posted text containing a string")]
struct Args {
    /// Mode: "execute" (test, no proof) or "prove" (generate ZK proof)
    #[arg(long, default_value = "execute")]
    mode: String,

    /// Account DID (e.g. did:plc:abc123)
    #[arg(long)]
    did: String,

    /// Record key (rkey) of the post
    #[arg(long)]
    rkey: String,

    /// String to search for in the post text
    #[arg(long)]
    search: String,

    /// PDS URL override (auto-resolved from DID if not set)
    #[arg(long)]
    pds: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("Resolving DID {}...", args.did);
    let did_info = resolve_did(&args.did)?;
    let pds = args
        .pds
        .or(did_info.pds_endpoint)
        .context("no PDS endpoint found (use --pds)")?;
    println!(
        "  key type: {:?}, pubkey: {} bytes, pds: {}",
        did_info.key_type,
        did_info.pubkey.len(),
        pds
    );

    let record_key = format!("app.bsky.feed.post/{}", args.rkey);
    println!("Fetching record proof for {}...", record_key);
    let car_bytes = fetch_record_car(&pds, &args.did, "app.bsky.feed.post", &args.rkey)?;
    println!("  CAR size: {} bytes", car_bytes.len());

    println!("Parsing CAR file...");
    let (root_cid, blocks) = parse_car(&car_bytes)?;
    println!("  root: {}, blocks: {}", root_cid, blocks.len());

    let commit_bytes = blocks
        .get(&root_cid)
        .context("commit block not found in CAR")?;

    let commit = extract_commit_proof_data(commit_bytes)?;
    println!("  commit.did: {}", commit.did);
    println!("  commit.rev: {}", commit.rev);
    println!(
        "  unsigned commit: {} bytes, sig: {} bytes",
        commit.unsigned_commit.len(),
        commit.signature.len()
    );

    println!("Extracting MST path...");
    let mst_path = extract_mst_path(&blocks, &commit.mst_root, &record_key)?;
    println!("  path depth: {} nodes", mst_path.len());

    let record_cid = find_record_cid(mst_path.last().unwrap(), &record_key)?;
    let record_bytes = blocks
        .get(&record_cid)
        .context("record block not found in CAR")?;
    println!("  record: {} bytes", record_bytes.len());

    let input = ProofInput {
        did: args.did,
        pubkey: did_info.pubkey,
        key_type: did_info.key_type,
        unsigned_commit: commit.unsigned_commit,
        signature: commit.signature,
        mst_nodes: mst_path,
        record: record_bytes.clone(),
        record_key,
        search_string: args.search,
    };

    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    match args.mode.as_str() {
        "execute" => {
            println!("Executing SP1 program (no proof)...");
            let (mut output, report) = client.execute(ELF, stdin).run()?;
            let result: ProofOutput = output.read();
            println!("---");
            println!("Cycles: {}", report.total_instruction_count());
            print_result(&result);
        }
        "prove" => {
            println!("Generating ZK proof...");
            let pk = client.setup(ELF)?;
            let mut proof = client.prove(&pk, stdin).run()?;
            let result: ProofOutput = proof.public_values.read();
            println!("Proof generated.");
            print_result(&result);

            println!("Verifying proof...");
            client.verify(&proof, pk.verifying_key(), None)?;
            println!("Proof verified successfully.");
        }
        other => bail!("unknown mode: {other}"),
    }

    Ok(())
}

fn print_result(r: &ProofOutput) {
    println!("DID: {}", r.did);
    println!("Search string: \"{}\"", r.search_string);
    println!(
        "Pubkey hash: {}",
        r.pubkey_hash
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    println!("Commit rev: {}", r.commit_rev);
}
