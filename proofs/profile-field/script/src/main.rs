use anyhow::{bail, Result};
use clap::Parser;
use sp1_sdk::{include_elf, Elf, SP1Stdin};
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::ProvingKey;
use zkat_host::prepare_record_proof;
use profile_field_lib::{ProofInput, ProofOutput, ProfileFieldTarget};

const ELF: Elf = include_elf!("profile-field-program");

#[derive(Parser)]
#[command(name = "profile-field", about = "Prove that a DID's profile field contains a string")]
struct Args {
    #[arg(long, default_value = "execute")]
    mode: String,
    #[arg(long)]
    did: String,
    /// Which profile field to check: "display-name" or "description"
    #[arg(long)]
    field: String,
    #[arg(long)]
    search: String,
    #[arg(long)]
    pds: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let field = match args.field.as_str() {
        "display-name" => ProfileFieldTarget::DisplayName,
        "description" => ProfileFieldTarget::Description,
        other => bail!("unknown field: {other} (expected display-name or description)"),
    };

    // Profile rkey is always "self"
    let proof = prepare_record_proof(&args.did, "app.bsky.actor.profile", "self", args.pds.as_deref())?;

    let input = ProofInput {
        did: args.did,
        pubkey: proof.did_info.pubkey,
        key_type: proof.did_info.key_type,
        unsigned_commit: proof.unsigned_commit,
        signature: proof.signature,
        mst_nodes: proof.mst_nodes,
        record: proof.record,
        record_key: proof.record_key,
        field,
        search_string: args.search,
    };

    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    match args.mode.as_str() {
        "execute" => {
            let (mut output, report) = client.execute(ELF, stdin).run()?;
            let r: ProofOutput = output.read();
            println!("Cycles: {}", report.total_instruction_count());
            println!("DID {} profile {:?} contains \"{}\"", r.did, r.field, r.search_string);
            println!("Pubkey hash: {}", r.pubkey_hash.iter().map(|b| format!("{b:02x}")).collect::<String>());
            println!("Commit rev: {}", r.commit_rev);
        }
        "prove" => {
            let pk = client.setup(ELF)?;
            let mut proof = client.prove(&pk, stdin).run()?;
            let r: ProofOutput = proof.public_values.read();
            println!("Proof generated. DID {} profile {:?} contains \"{}\"", r.did, r.field, r.search_string);
            client.verify(&proof, pk.verifying_key(), None)?;
            println!("Proof verified.");
        }
        other => bail!("unknown mode: {other}"),
    }
    Ok(())
}
