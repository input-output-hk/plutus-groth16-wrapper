//! Deserializer for the gnark-dumped InnerVKHash test vectors
//! (`testdata/inner_vk_hash_vectors.json`). Test-only; the fixture is the
//! reference oracle for the Rust Poseidon2 / VK-hash port.

// The fixture structs mirror the full JSON schema for documentation; not every
// field is asserted in every test.
#![allow(dead_code)]

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Vectors {
    pub seed: String,
    pub params: Params,
    pub round_keys: Vec<Vec<String>>,
    pub perm_kats: Vec<PermKat>,
    pub md_kats: Vec<MdKat>,
    pub vk: Vk,
}

#[derive(Debug, Deserialize)]
pub struct Params {
    pub width: usize,
    pub nb_full_rounds: usize,
    pub nb_partial_rounds: usize,
    pub sbox_degree: usize,
}

#[derive(Debug, Deserialize)]
pub struct PermKat {
    pub r#in: Vec<String>,
    pub out: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct MdKat {
    pub blocks: Vec<String>,
    pub digest: String,
}

#[derive(Debug, Deserialize)]
pub struct Vk {
    pub max_inputs: usize,
    pub n_real: usize,
    pub vk_bytes_hex: String,
    pub gt_limbs: Vec<String>,
    pub gamma_neg: Vec<String>,
    pub delta_neg: Vec<String>,
    pub ic: Vec<Vec<String>>,
    pub limb_seq_u64: Vec<u64>,
    pub inner_vk_hash: String,
}

const FIXTURE: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/inner_vk_hash_vectors.json"));

pub fn load_vectors() -> Vectors {
    serde_json::from_str(FIXTURE).expect("parse inner_vk_hash_vectors.json")
}
