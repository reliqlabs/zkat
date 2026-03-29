use anyhow::{bail, Context, Result};
use clap::Parser;
use sp1_sdk::{include_elf, Elf, SP1Stdin};
use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient};
use sp1_sdk::ProvingKey;
use zkat_host::{
    resolve_did, fetch_record_car, parse_car, extract_commit_proof_data,
    extract_mst_path, find_record_cid,
};
use not_following_lib::{FollowEntry, ProofInput, ProofOutput};

const ELF: Elf = include_elf!("not-following-program");

#[derive(Parser)]
#[command(name = "not-following", about = "Prove that a DID does NOT follow another DID")]
struct Args {
    #[arg(long, default_value = "execute")]
    mode: String,
    #[arg(long)]
    did: String,
    #[arg(long)]
    target: String,
    #[arg(long)]
    pds: Option<String>,
}

#[derive(serde::Deserialize)]
struct ListRecordsResponse {
    records: Vec<RecordEntry>,
    cursor: Option<String>,
}

#[derive(serde::Deserialize)]
struct RecordEntry {
    uri: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("Resolving DID...");
    let did_info = resolve_did(&args.did)?;
    let pds = args.pds.clone()
        .or(did_info.pds_endpoint.clone())
        .context("no PDS endpoint found (use --pds)")?;

    // List all follow records
    println!("Listing all follow records...");
    let mut rkeys = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut url = format!(
            "{}/xrpc/com.atproto.repo.listRecords?repo={}&collection=app.bsky.graph.follow&limit=100",
            pds, args.did
        );
        if let Some(ref c) = cursor {
            url.push_str(&format!("&cursor={}", c));
        }
        let resp: ListRecordsResponse = reqwest::blocking::get(&url)?.json()?;
        for rec in &resp.records {
            // Extract rkey from URI: at://did/collection/rkey
            let rkey = rec.uri.rsplit('/').next().unwrap().to_string();
            rkeys.push(rkey);
        }
        cursor = resp.cursor;
        if cursor.is_none() { break; }
    }
    println!("  found {} follow records", rkeys.len());

    // Fetch MST proofs for each follow record
    println!("Fetching MST proofs for each follow record...");
    let mut follows = Vec::new();
    let mut commit_data = None;

    for (i, rkey) in rkeys.iter().enumerate() {
        let car_bytes = fetch_record_car(&pds, &args.did, "app.bsky.graph.follow", rkey)?;
        let (root_cid, blocks) = parse_car(&car_bytes)?;
        let commit_bytes = blocks.get(&root_cid).context("no commit block in CAR")?;

        if commit_data.is_none() {
            commit_data = Some(extract_commit_proof_data(commit_bytes)?);
        }
        let cd = commit_data.as_ref().unwrap();
        let record_key = format!("app.bsky.graph.follow/{}", rkey);

        let mst_path = extract_mst_path(&blocks, &cd.mst_root, &record_key)?;
        let record_cid = find_record_cid(mst_path.last().unwrap(), &record_key)?;
        let record = blocks.get(&record_cid).context("record block not found in CAR")?.clone();

        follows.push(FollowEntry {
            mst_nodes: mst_path,
            record,
            record_key,
        });

        if (i + 1) % 50 == 0 {
            println!("  processed {}/{}", i + 1, rkeys.len());
        }
    }

    let cd = commit_data.context("no follow records found — account follows nobody")?;
    println!("Building proof input...");

    let input = ProofInput {
        did: args.did.clone(),
        pubkey: did_info.pubkey,
        key_type: did_info.key_type,
        unsigned_commit: cd.unsigned_commit,
        signature: cd.signature,
        follows,
        target_did: args.target.clone(),
        expected_count: rkeys.len() as u64,
    };

    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    match args.mode.as_str() {
        "execute" => {
            let (mut output, report) = client.execute(ELF, stdin).run()?;
            let r: ProofOutput = output.read();
            println!("Cycles: {}", report.total_instruction_count());
            println!("{} does NOT follow {} (checked {} follow records)", r.did, r.target_did, r.follow_count);
            println!("Pubkey hash: {}", r.pubkey_hash.iter().map(|b| format!("{b:02x}")).collect::<String>());
            println!("Commit rev: {}", r.commit_rev);
        }
        "prove" => {
            let pk = client.setup(ELF)?;
            let mut proof = client.prove(&pk, stdin).run()?;
            let r: ProofOutput = proof.public_values.read();
            println!("Proof generated. {} does NOT follow {}", r.did, r.target_did);
            client.verify(&proof, pk.verifying_key(), None)?;
            println!("Proof verified.");
        }
        other => bail!("unknown mode: {other}"),
    }
    Ok(())
}
