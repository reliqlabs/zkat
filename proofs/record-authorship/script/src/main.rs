use anyhow::{bail, Result};
use clap::Parser;
use record_authorship_lib::{ProofInput, ProofOutput};
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::ProvingKey;
use sp1_sdk::{include_elf, Elf, SP1Stdin};
use zkat_host::prepare_record_proof;

const ELF: Elf = include_elf!("record-authorship-program");

#[derive(Parser)]
#[command(
    name = "record-authorship",
    about = "Prove that a DID authored a record with a specific content hash"
)]
struct Args {
    #[arg(long, default_value = "execute")]
    mode: String,
    #[arg(long)]
    did: String,
    #[arg(long)]
    collection: String,
    #[arg(long)]
    rkey: String,
    #[arg(long)]
    pds: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let proof = prepare_record_proof(
        &args.did,
        &args.collection,
        &args.rkey,
        args.pds.as_deref(),
    )?;

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
            println!("Record: {}", r.record_key);
            println!(
                "Record hash: {}",
                r.record_hash
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            println!(
                "Pubkey hash: {}",
                r.pubkey_hash
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            println!("Commit rev: {}", r.commit_rev);
        }
        "prove" => {
            let pk = client.setup(ELF)?;
            let mut proof = client.prove(&pk, stdin).run()?;
            let r: ProofOutput = proof.public_values.read();
            println!("Proof generated. DID {} authored {}", r.did, r.record_key);
            client.verify(&proof, pk.verifying_key(), None)?;
            println!("Proof verified.");
        }
        other => bail!("unknown mode: {other}"),
    }
    Ok(())
}
