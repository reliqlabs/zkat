use anyhow::{bail, Result};
use clap::Parser;
use sp1_sdk::{include_elf, Elf, SP1Stdin};
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::ProvingKey;
use zkat_host::prepare_record_proof;
use post_timestamp_lib::{ProofInput, ProofOutput};

const ELF: Elf = include_elf!("post-timestamp-program");

#[derive(Parser)]
#[command(name = "post-timestamp", about = "Prove that a DID made a post before or after a timestamp")]
struct Args {
    #[arg(long, default_value = "execute")]
    mode: String,
    #[arg(long)]
    did: String,
    #[arg(long)]
    rkey: String,
    /// ISO 8601 timestamp boundary
    #[arg(long)]
    boundary: String,
    /// Prove the post was created before the boundary (default: after)
    #[arg(long)]
    before: bool,
    #[arg(long)]
    pds: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let proof = prepare_record_proof(&args.did, "app.bsky.feed.post", &args.rkey, args.pds.as_deref())?;

    let input = ProofInput {
        did: args.did,
        pubkey: proof.did_info.pubkey,
        key_type: proof.did_info.key_type,
        unsigned_commit: proof.unsigned_commit,
        signature: proof.signature,
        mst_nodes: proof.mst_nodes,
        record: proof.record,
        record_key: proof.record_key,
        boundary: args.boundary,
        before: args.before,
    };

    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    match args.mode.as_str() {
        "execute" => {
            let (mut output, report) = client.execute(ELF, stdin).run()?;
            let r: ProofOutput = output.read();
            println!("Cycles: {}", report.total_instruction_count());
            let dir = if r.before { "before" } else { "on or after" };
            println!("DID {} posted {} {}", r.did, dir, r.boundary);
            println!("Pubkey hash: {}", r.pubkey_hash.iter().map(|b| format!("{b:02x}")).collect::<String>());
            println!("Commit rev: {}", r.commit_rev);
        }
        "prove" => {
            let pk = client.setup(ELF)?;
            let mut proof = client.prove(&pk, stdin).run()?;
            let r: ProofOutput = proof.public_values.read();
            let dir = if r.before { "before" } else { "on or after" };
            println!("Proof generated. DID {} posted {} {}", r.did, dir, r.boundary);
            client.verify(&proof, pk.verifying_key(), None)?;
            println!("Proof verified.");
        }
        other => bail!("unknown mode: {other}"),
    }
    Ok(())
}
