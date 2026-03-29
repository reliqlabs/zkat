use std::collections::HashMap;
use std::io::Cursor;

use anyhow::{bail, Context, Result};
use cid::Cid;
use ipld_core::cid::Cid as IpldCid;
use zkat_core::KeyType;

// -- DID resolution --

pub struct DidInfo {
    pub pubkey: Vec<u8>,
    pub key_type: KeyType,
    pub pds_endpoint: Option<String>,
}

pub fn resolve_did(did: &str) -> Result<DidInfo> {
    let url = format!("https://plc.directory/{did}");
    let resp: serde_json::Value = reqwest::blocking::get(&url)?.json()?;

    let methods = resp["verificationMethod"]
        .as_array()
        .context("no verificationMethod in DID doc")?;

    let atproto_vm = methods
        .iter()
        .find(|v| {
            v["id"]
                .as_str()
                .map_or(false, |id| id.ends_with("#atproto"))
        })
        .context("no #atproto verification method")?;

    let multibase = atproto_vm["publicKeyMultibase"]
        .as_str()
        .context("no publicKeyMultibase")?;

    if !multibase.starts_with('z') {
        bail!("expected base58btc (z prefix), got: {}", &multibase[..1]);
    }
    let decoded = bs58::decode(&multibase[1..]).into_vec()?;

    if decoded.len() < 2 {
        bail!("multicodec key too short");
    }

    let (key_type, pubkey) = if decoded.starts_with(&[0x80, 0x24]) {
        (KeyType::P256, decoded[2..].to_vec())
    } else if decoded.starts_with(&[0xe7, 0x01]) {
        (KeyType::Secp256k1, decoded[2..].to_vec())
    } else {
        bail!(
            "unknown key multicodec: 0x{:02x}{:02x}",
            decoded[0],
            decoded[1]
        );
    };

    let pds_endpoint = resp["service"]
        .as_array()
        .and_then(|services| {
            services
                .iter()
                .find(|s| s["id"].as_str() == Some("#atproto_pds"))
        })
        .and_then(|s| s["serviceEndpoint"].as_str())
        .map(|s| s.to_string());

    Ok(DidInfo {
        pubkey,
        key_type,
        pds_endpoint,
    })
}

// -- PDS fetching --

pub fn fetch_record_car(pds: &str, did: &str, collection: &str, rkey: &str) -> Result<Vec<u8>> {
    let url = format!(
        "{pds}/xrpc/com.atproto.sync.getRecord?did={did}&collection={collection}&rkey={rkey}"
    );
    let resp = reqwest::blocking::get(&url)?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        bail!("PDS returned {status}: {body}");
    }
    Ok(resp.bytes()?.to_vec())
}

// -- CAR v1 parsing --

#[derive(serde::Deserialize)]
struct CarHeader {
    version: u64,
    roots: Vec<IpldCid>,
}

pub fn parse_car(data: &[u8]) -> Result<(Cid, HashMap<Cid, Vec<u8>>)> {
    let mut pos = 0;

    let (header_len, n) = read_varint(&data[pos..])?;
    pos += n;
    let header_end = pos + header_len as usize;
    let header: CarHeader = serde_ipld_dagcbor::from_slice(&data[pos..header_end])?;
    pos = header_end;

    if header.version != 1 {
        bail!("only CAR v1 supported, got v{}", header.version);
    }
    let root = header
        .roots
        .into_iter()
        .next()
        .context("CAR has no roots")?;

    let root_cid = ipld_cid_to_cid(&root);

    let mut blocks = HashMap::new();
    while pos < data.len() {
        let (block_len, n) = read_varint(&data[pos..])?;
        pos += n;
        let block_end = pos + block_len as usize;
        if block_end > data.len() {
            bail!("CAR block extends past EOF");
        }
        let block_data = &data[pos..block_end];

        let mut cursor = Cursor::new(block_data);
        let block_cid = Cid::read_bytes(&mut cursor)?;
        let cid_len = cursor.position() as usize;
        let content = block_data[cid_len..].to_vec();

        blocks.insert(block_cid, content);
        pos = block_end;
    }

    Ok((root_cid, blocks))
}

// -- Commit extraction --

#[derive(serde::Deserialize)]
struct SignedCommit {
    did: String,
    rev: String,
    #[serde(with = "serde_bytes")]
    sig: Vec<u8>,
    data: IpldCid,
    prev: Option<IpldCid>,
    version: u64,
}

/// Field order follows DAG-CBOR sort (by key length, then lex):
/// did(3), rev(3), data(4), prev(4), version(7).
#[derive(serde::Serialize)]
struct UnsignedCommit {
    did: String,
    rev: String,
    data: IpldCid,
    prev: Option<IpldCid>,
    version: u64,
}

pub struct CommitProofData {
    pub unsigned_commit: Vec<u8>,
    pub signature: Vec<u8>,
    pub mst_root: IpldCid,
    pub did: String,
    pub rev: String,
}

/// Parse the signed commit block, returning the unsigned bytes + signature for proof input.
pub fn extract_commit_proof_data(commit_bytes: &[u8]) -> Result<CommitProofData> {
    let signed: SignedCommit = serde_ipld_dagcbor::from_slice(commit_bytes)?;

    let unsigned = UnsignedCommit {
        did: signed.did.clone(),
        rev: signed.rev.clone(),
        data: signed.data.clone(),
        prev: signed.prev.clone(),
        version: signed.version,
    };
    let unsigned_commit = serde_ipld_dagcbor::to_vec(&unsigned)?;

    Ok(CommitProofData {
        unsigned_commit,
        signature: signed.sig,
        mst_root: signed.data,
        did: signed.did,
        rev: signed.rev,
    })
}

// -- MST path extraction --

#[derive(serde::Deserialize)]
struct MstNode {
    #[serde(rename = "l")]
    left: Option<IpldCid>,
    #[serde(rename = "e")]
    entries: Vec<TreeEntry>,
}

#[derive(serde::Deserialize)]
struct TreeEntry {
    #[serde(rename = "p")]
    prefix_len: u32,
    #[serde(rename = "k", with = "serde_bytes")]
    key_suffix: Vec<u8>,
    #[serde(rename = "v")]
    value: IpldCid,
    #[serde(rename = "t")]
    tree: Option<IpldCid>,
}

/// Walk the MST from `root` to find `record_key`, returning the ordered node bytes.
pub fn extract_mst_path(
    blocks: &HashMap<Cid, Vec<u8>>,
    root: &IpldCid,
    record_key: &str,
) -> Result<Vec<Vec<u8>>> {
    let mut path = Vec::new();
    let mut current = ipld_cid_to_cid(root);

    loop {
        let node_bytes = blocks
            .get(&current)
            .with_context(|| format!("MST node {} not found in CAR", current))?;
        path.push(node_bytes.clone());

        let node: MstNode = serde_ipld_dagcbor::from_slice(node_bytes)?;
        let target = record_key.as_bytes();

        let mut prev_key: Vec<u8> = Vec::new();
        let mut next_cid: Option<&IpldCid> = None;
        let mut found_record = false;

        for (i, entry) in node.entries.iter().enumerate() {
            let key = reconstruct_key(&prev_key, entry.prefix_len as usize, &entry.key_suffix);

            match target.cmp(key.as_slice()) {
                std::cmp::Ordering::Less => {
                    next_cid = if i == 0 {
                        node.left.as_ref()
                    } else {
                        node.entries[i - 1].tree.as_ref()
                    };
                    break;
                }
                std::cmp::Ordering::Equal => {
                    found_record = true;
                    break;
                }
                std::cmp::Ordering::Greater => {
                    prev_key = key;
                }
            }
        }

        if found_record {
            return Ok(path);
        }

        if next_cid.is_none() {
            // Target is after all entries — follow last entry's right subtree,
            // or the left pointer if there are no entries.
            next_cid = node
                .entries
                .last()
                .and_then(|e| e.tree.as_ref())
                .or(node.left.as_ref());
        }

        let cid = next_cid.context("record key not found in MST (no subtree to follow)")?;
        current = ipld_cid_to_cid(cid);
    }
}

/// Find the record's CID in the leaf MST node.
pub fn find_record_cid(leaf_node_bytes: &[u8], record_key: &str) -> Result<Cid> {
    let node: MstNode = serde_ipld_dagcbor::from_slice(leaf_node_bytes)?;
    let target = record_key.as_bytes();
    let mut prev_key: Vec<u8> = Vec::new();

    for entry in &node.entries {
        let key = reconstruct_key(&prev_key, entry.prefix_len as usize, &entry.key_suffix);
        if key.as_slice() == target {
            return Ok(ipld_cid_to_cid(&entry.value));
        }
        prev_key = key;
    }
    bail!("record key not found in MST leaf node");
}

// -- helpers --

fn ipld_cid_to_cid(c: &IpldCid) -> Cid {
    Cid::read_bytes(Cursor::new(c.to_bytes())).expect("CID conversion failed")
}

fn read_varint(data: &[u8]) -> Result<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for (i, &byte) in data.iter().enumerate() {
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            bail!("varint overflow");
        }
    }
    bail!("unexpected EOF in varint");
}

fn reconstruct_key(prev_key: &[u8], prefix_len: usize, suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix_len + suffix.len());
    if prefix_len > 0 {
        key.extend_from_slice(&prev_key[..prefix_len]);
    }
    key.extend_from_slice(suffix);
    key
}

// -- High-level proof preparation --

/// All the data needed to construct a single-record ZK proof input.
pub struct RecordProof {
    pub did_info: DidInfo,
    pub pds: String,
    pub unsigned_commit: Vec<u8>,
    pub signature: Vec<u8>,
    pub mst_nodes: Vec<Vec<u8>>,
    pub record: Vec<u8>,
    pub record_key: String,
    pub commit_rev: String,
}

/// Fetch and prepare everything needed for a single-record inclusion proof.
pub fn prepare_record_proof(
    did: &str,
    collection: &str,
    rkey: &str,
    pds_override: Option<&str>,
) -> Result<RecordProof> {
    let did_info = resolve_did(did)?;
    let pds = pds_override
        .map(|s| s.to_string())
        .or_else(|| did_info.pds_endpoint.clone())
        .context("no PDS endpoint found (use --pds)")?;

    let car_bytes = fetch_record_car(&pds, did, collection, rkey)?;
    let (root_cid, blocks) = parse_car(&car_bytes)?;
    let commit_bytes = blocks
        .get(&root_cid)
        .context("commit block not found in CAR")?;
    let commit = extract_commit_proof_data(commit_bytes)?;
    let record_key = format!("{collection}/{rkey}");
    let mst_path = extract_mst_path(&blocks, &commit.mst_root, &record_key)?;
    let record_cid = find_record_cid(mst_path.last().unwrap(), &record_key)?;
    let record = blocks
        .get(&record_cid)
        .context("record block not found in CAR")?
        .clone();

    Ok(RecordProof {
        did_info,
        pds,
        unsigned_commit: commit.unsigned_commit,
        signature: commit.signature,
        mst_nodes: mst_path,
        record,
        record_key,
        commit_rev: commit.rev,
    })
}
