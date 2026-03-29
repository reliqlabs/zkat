use anyhow::{bail, Result};
use clap::Parser;
use sp1_sdk::{include_elf, Elf, SP1Stdin};
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::ProvingKey;
use zkat_host::prepare_record_proof;
use selective_disclosure_lib::{FieldAssertion, ProofInput, ProofOutput};

const ELF: Elf = include_elf!("selective-disclosure-program");

#[derive(Parser)]
#[command(name = "selective-disclosure", about = "Prove specific fields of a record have specific values")]
struct Args {
    #[arg(long, default_value = "execute")]
    mode: String,
    #[arg(long)]
    did: String,
    #[arg(long)]
    collection: String,
    #[arg(long)]
    rkey: String,
    /// Field assertions as "field=value" pairs
    #[arg(long = "assert", value_name = "FIELD=VALUE")]
    assertions: Vec<String>,
    #[arg(long)]
    pds: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let assertions: Vec<FieldAssertion> = args.assertions.iter().map(|a| {
        let (field, value) = a.split_once('=').expect("assertion must be field=value");
        FieldAssertion { field: field.to_string(), value: value.to_string() }
    }).collect();

    let proof = prepare_record_proof(&args.did, &args.collection, &args.rkey, args.pds.as_deref())?;

    let input = ProofInput {
        did: args.did,
        pubkey: proof.did_info.pubkey,
        key_type: proof.did_info.key_type,
        unsigned_commit: proof.unsigned_commit,
        signature: proof.signature,
        mst_nodes: proof.mst_nodes,
        record: proof.record,
        record_key: proof.record_key,
        assertions: assertions.clone(),
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
            for a in &r.assertions {
                println!("  {} = {}", a.field, a.value);
            }
            println!("Pubkey hash: {}", r.pubkey_hash.iter().map(|b| format!("{b:02x}")).collect::<String>());
            println!("Commit rev: {}", r.commit_rev);
        }
        "prove" => {
            let pk = client.setup(ELF)?;
            let mut proof = client.prove(&pk, stdin).run()?;
            let r: ProofOutput = proof.public_values.read();
            println!("Proof generated for {} assertions on {}", r.assertions.len(), r.record_key);
            client.verify(&proof, pk.verifying_key(), None)?;
            println!("Proof verified.");
        }
        other => bail!("unknown mode: {other}"),
    }
    Ok(())
}
