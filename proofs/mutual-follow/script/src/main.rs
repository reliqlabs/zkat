use anyhow::{bail, Result};
use clap::Parser;
use sp1_sdk::{include_elf, Elf, SP1Stdin};
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::ProvingKey;
use zkat_host::prepare_record_proof;
use mutual_follow_lib::{FollowWitness, ProofInput, ProofOutput};

const ELF: Elf = include_elf!("mutual-follow-program");

#[derive(Parser)]
#[command(name = "mutual-follow", about = "Prove that two DIDs follow each other")]
struct Args {
    #[arg(long, default_value = "execute")]
    mode: String,
    #[arg(long)]
    did_a: String,
    #[arg(long)]
    rkey_a: String,
    #[arg(long)]
    did_b: String,
    #[arg(long)]
    rkey_b: String,
    #[arg(long)]
    pds: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("Fetching A's follow of B...");
    let a = prepare_record_proof(&args.did_a, "app.bsky.graph.follow", &args.rkey_a, args.pds.as_deref())?;
    println!("Fetching B's follow of A...");
    let b = prepare_record_proof(&args.did_b, "app.bsky.graph.follow", &args.rkey_b, args.pds.as_deref())?;

    let input = ProofInput {
        a_follows_b: FollowWitness {
            did: args.did_a.clone(),
            pubkey: a.did_info.pubkey,
            key_type: a.did_info.key_type,
            unsigned_commit: a.unsigned_commit,
            signature: a.signature,
            mst_nodes: a.mst_nodes,
            record: a.record,
            record_key: a.record_key,
        },
        b_follows_a: FollowWitness {
            did: args.did_b.clone(),
            pubkey: b.did_info.pubkey,
            key_type: b.did_info.key_type,
            unsigned_commit: b.unsigned_commit,
            signature: b.signature,
            mst_nodes: b.mst_nodes,
            record: b.record,
            record_key: b.record_key,
        },
        did_a: args.did_a,
        did_b: args.did_b,
    };

    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    match args.mode.as_str() {
        "execute" => {
            let (mut output, report) = client.execute(ELF, stdin).run()?;
            let r: ProofOutput = output.read();
            println!("Cycles: {}", report.total_instruction_count());
            println!("{} and {} mutually follow each other", r.did_a, r.did_b);
            println!("Pubkey hash A: {}", r.pubkey_hash_a.iter().map(|b| format!("{b:02x}")).collect::<String>());
            println!("Pubkey hash B: {}", r.pubkey_hash_b.iter().map(|b| format!("{b:02x}")).collect::<String>());
            println!("Commit rev A: {}", r.commit_rev_a);
            println!("Commit rev B: {}", r.commit_rev_b);
        }
        "prove" => {
            let pk = client.setup(ELF)?;
            let mut proof = client.prove(&pk, stdin).run()?;
            let r: ProofOutput = proof.public_values.read();
            println!("Proof generated. {} and {} mutually follow", r.did_a, r.did_b);
            client.verify(&proof, pk.verifying_key(), None)?;
            println!("Proof verified.");
        }
        other => bail!("unknown mode: {other}"),
    }
    Ok(())
}
