use anyhow::{bail, Result};
use clap::Parser;
use sp1_sdk::{include_elf, Elf, SP1Stdin};
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::ProvingKey;
use zkat_host::prepare_record_proof;
use post_authorship_lib::{ProofInput, ProofOutput};

const ELF: Elf = include_elf!("post-authorship-program");

#[derive(Parser)]
#[command(name = "post-authorship", about = "Prove that a DID authored a post with a specific content hash")]
struct Args {
    #[arg(long, default_value = "execute")]
    mode: String,
    #[arg(long)]
    did: String,
    #[arg(long)]
    rkey: String,
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
    };

    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    match args.mode.as_str() {
        "execute" => {
            let (mut output, report) = client.execute(ELF, stdin).run()?;
            let r: ProofOutput = output.read();
            println!("Cycles: {}", report.total_instruction_count());
            println!("DID: {}", r.did);
            println!("Record hash: {}", r.record_hash.iter().map(|b| format!("{b:02x}")).collect::<String>());
            println!("Pubkey hash: {}", r.pubkey_hash.iter().map(|b| format!("{b:02x}")).collect::<String>());
            println!("Commit rev: {}", r.commit_rev);
        }
        "prove" => {
            let pk = client.setup(ELF)?;
            let mut proof = client.prove(&pk, stdin).run()?;
            let r: ProofOutput = proof.public_values.read();
            println!("Proof generated. DID {} authored record", r.did);
            client.verify(&proof, pk.verifying_key(), None)?;
            println!("Proof verified.");
        }
        other => bail!("unknown mode: {other}"),
    }
    Ok(())
}
