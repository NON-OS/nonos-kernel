//! Halo2 host verifier (KZG/Bn256, Blake2b transcript)

#![cfg(feature = "zk-halo2")]

extern crate alloc;
use alloc::vec::Vec;

use core::fmt;
// use std::io::Cursor; // Not available in no_std

use halo2_proofs::{
    plonk::{self, VerifyingKey},
    poly::{
        commitment::Params,
        kzg::{commitment::ParamsKZG, strategy::SingleStrategy},
    },
    transcript::{Blake2bRead, Challenge255},
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2curves::ff::PrimeField;

// Global bounds to mitigate DoS and accidental misuse
const MAX_PARAMS_BYTES: usize = 32 * 1024 * 1024; // 32 MiB
const MAX_VK_BYTES: usize = 16 * 1024 * 1024;     // 16 MiB
const MAX_PROOF_BYTES: usize = 32 * 1024 * 1024;  // 32 MiB
const MAX_PUBLIC_INPUTS: usize = 1 << 20;         // 1,048,576 total elements cap
const MIN_K: u32 = 8;
const MAX_K: u32 = 26;

#[derive(Debug)]
pub enum Halo2Error {
    Deserialize(&'static str),
    SizeLimit(&'static str),
    PublicInputShape,
    KOutOfRange,
    VerifyFailed,
}

impl fmt::Display for Halo2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Halo2Error::Deserialize(m) => write!(f, "deserialize error: {}", m),
            Halo2Error::SizeLimit(m) => write!(f, "size exceeds limit: {}", m),
            Halo2Error::PublicInputShape => write!(f, "public input shape mismatch"),
            Halo2Error::KOutOfRange => write!(f, "params k is out of accepted range"),
            Halo2Error::VerifyFailed => write!(f, "proof verification failed"),
        }
    }
}

fn read_params(params_bytes: &[u8]) -> Result<ParamsKZG<Bn256>, Halo2Error> {
    if params_bytes.len() > MAX_PARAMS_BYTES {
        return Err(Halo2Error::SizeLimit("params"));
    }
    let params = ParamsKZG::<Bn256>::read(&mut Cursor::new(params_bytes))
        .map_err(|_| Halo2Error::Deserialize("params"))?;
    let k = params.k();
    if k < MIN_K || k > MAX_K {
        return Err(Halo2Error::KOutOfRange);
    }
    Ok(params)
}

fn read_vk(params: &ParamsKZG<Bn256>, vk_bytes: &[u8]) -> Result<VerifyingKey<G1Affine>, Halo2Error> {
    if vk_bytes.len() > MAX_VK_BYTES {
        return Err(Halo2Error::SizeLimit("verifying key"));
    }
    VerifyingKey::<G1Affine>::read::<_, _>(params, &mut Cursor::new(vk_bytes))
        .map_err(|_| Halo2Error::Deserialize("verifying key"))
}

fn columns_from_le_fr(columns_le: &[&[[u8; 32]]]) -> Result<Vec<Vec<Fr>>, Halo2Error> {
    let mut total = 0usize;
    let mut out: Vec<Vec<Fr>> = Vec::with_capacity(columns_le.len());
    for col in columns_le {
        let mut v = Vec::with_capacity(col.len());
        for bytes in *col {
            let opt = Fr::from_bytes(bytes);
            if bool::from(opt.is_some()) {
                v.push(opt.unwrap());
            } else {
                return Err(Halo2Error::Deserialize("public input Fr"));
            }
        }
        total = total.saturating_add(v.len());
        if total > MAX_PUBLIC_INPUTS {
            return Err(Halo2Error::SizeLimit("public inputs"));
        }
        out.push(v);
    }
    Ok(out)
}

/// Reusable Halo2 verifier that caches Params and VerifyingKey.
pub struct Halo2Verifier {
    params: ParamsKZG<Bn256>,
    vk: VerifyingKey<G1Affine>,
    expected_cols: Vec<usize>,
}

impl Halo2Verifier {
    /// Construct a verifier from serialized params and verifying key.
    pub fn from_bytes(params_bytes: &[u8], vk_bytes: &[u8]) -> Result<Self, Halo2Error> {
        let params = read_params(params_bytes)?;
        let vk = read_vk(&params, vk_bytes)?;
        let expected_cols = vk.num_instance();
        Ok(Self { params, vk, expected_cols })
    }

    /// Return params k.
    pub fn k(&self) -> u32 { self.params.k() }

    /// Return expected public instance column lengths (per-column).
    pub fn expected_instance_cols(&self) -> &[usize] { &self.expected_cols }

    /// Verify a single proof with per-column public inputs (Fr as 32-byte LE).
    pub fn verify(&self, proof_bytes: &[u8], public_inputs_columns_le32: &[&[[u8; 32]]]) -> Result<(), Halo2Error> {
        if proof_bytes.len() > MAX_PROOF_BYTES {
            return Err(Halo2Error::SizeLimit("proof"));
        }
        if self.expected_cols.len() != public_inputs_columns_le32.len() {
            return Err(Halo2Error::PublicInputShape);
        }
        let mut cols = columns_from_le_fr(public_inputs_columns_le32)?;
        for (i, exp_len) in self.expected_cols.iter().enumerate() {
            if cols[i].len() != *exp_len {
                return Err(Halo2Error::PublicInputShape);
            }
        }

        let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(Cursor::new(proof_bytes));
        let strategy = SingleStrategy::new(&self.params);

        let mut col_refs: Vec<&[Fr]> = Vec::with_capacity(cols.len());
        for c in &cols { col_refs.push(c.as_slice()); }

        plonk::verify_proof(&self.params, &self.vk, strategy, &[col_refs.as_slice()], &mut transcript)
            .map_err(|_| Halo2Error::VerifyFailed)
    }

    /// Verify multiple proofs sequentially (same params+vk), each with its own public inputs.
    pub fn verify_many(
        &self,
        proofs: &[&[u8]],
        public_inputs_columns_list: &[&[&[[u8; 32]]]],
    ) -> Result<(), Halo2Error> {
        if proofs.len() != public_inputs_columns_list.len() {
            return Err(Halo2Error::PublicInputShape);
        }
        for (proof_bytes, columns_le) in proofs.iter().zip(public_inputs_columns_list.iter()) {
            self.verify(proof_bytes, columns_le)?;
        }
        Ok(())
    }
}

/// One-shot verification (constructs verifier internally).
pub fn halo2_verify_kzg_bn256(
    params_bytes: &[u8],
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs_columns_le32: &[&[[u8; 32]]],
) -> Result<(), Halo2Error> {
    let verifier = Halo2Verifier::from_bytes(params_bytes, vk_bytes)?;
    verifier.verify(proof_bytes, public_inputs_columns_le32)
}
