// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use std::{fs, path::PathBuf};

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use clap::Parser;

use nonos_attestation_circuit::{
    compute_capsule_commitment, expected_program_hash_bytes, BuildProvenance,
    NonosAttestationCircuit, PCR_PREIMAGE_LEN, MIN_HW_LEVEL,
};

#[derive(Parser, Debug)]
#[command(name = "generate-proof", about = "Generate Groth16 proof for NONOS boot attestation")]
struct Args {
    #[arg(short = 'k', long, value_name = "FILE")]
    proving_key: PathBuf,

    #[arg(short = 'o', long, value_name = "FILE")]
    output: PathBuf,

    #[arg(long, value_name = "FILE")]
    public_inputs_out: Option<PathBuf>,

    #[arg(long, value_name = "FILE")]
    provenance: Option<PathBuf>,

    #[arg(long, default_value = "nonos-boot-attestation")]
    seed: String,

    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    verbose: bool,
}

fn main() -> Result<(), String> {
    let args = Args::parse();

    println!("=== NONOS ZK Proof Generator ===");
    println!();

    println!("Loading proving key from: {}", args.proving_key.display());
    let pk_bytes = fs::read(&args.proving_key)
        .map_err(|e| format!("Failed to read proving key: {e}"))?;

    let pk: ProvingKey<Bls12_381> = ProvingKey::deserialize_with_mode(
        &pk_bytes[..],
        Compress::Yes,
        ark_serialize::Validate::Yes,
    ).map_err(|e| format!("Failed to deserialize proving key: {e}"))?;

    println!("  Proving key loaded ({} bytes)", pk_bytes.len());
    println!();

    let program_hash = expected_program_hash_bytes();
    println!("Program hash: {}", hex::encode(&program_hash));

    let mut pcr_preimage = [0u8; PCR_PREIMAGE_LEN];
    let mut hasher = blake3::Hasher::new();
    hasher.update(args.seed.as_bytes());
    hasher.update(b"pcr_preimage");
    let hash = hasher.finalize();
    pcr_preimage[..32].copy_from_slice(hash.as_bytes());
    pcr_preimage[32..].copy_from_slice(hash.as_bytes());

    let hardware_attestation = MIN_HW_LEVEL + 0x1000;

    let mut public_input_seed = Vec::new();
    public_input_seed.extend_from_slice(&program_hash);
    public_input_seed.extend_from_slice(&pcr_preimage);
    let capsule_commitment = compute_capsule_commitment(&public_input_seed);

    println!("Capsule commitment: {}", hex::encode(&capsule_commitment));
    println!("Hardware attestation level: 0x{:X}", hardware_attestation);
    println!();

    let circuit = if let Some(ref provenance_path) = args.provenance {
        println!("Loading build provenance from: {}", provenance_path.display());
        let provenance_bytes = fs::read(provenance_path)
            .map_err(|e| format!("Failed to read provenance file: {e}"))?;

        if provenance_bytes.len() != 160 {
            return Err(format!(
                "Invalid provenance file size: {} (expected 160)",
                provenance_bytes.len()
            ));
        }

        let mut prov_data = [0u8; 128];
        prov_data.copy_from_slice(&provenance_bytes[..128]);
        let provenance = BuildProvenance::from_bytes(&prov_data);

        let mut expected_hash = [0u8; 32];
        expected_hash.copy_from_slice(&provenance_bytes[128..160]);

        let computed_hash = provenance.compute_composite_hash();
        if computed_hash != expected_hash {
            return Err("provenance hash mismatch - file may be corrupted".into());
        }

        println!("  provenance composite hash: {}", hex::encode(&expected_hash));
        println!();

        NonosAttestationCircuit::<Fr>::with_build_provenance(
            capsule_commitment,
            program_hash,
            pcr_preimage,
            hardware_attestation,
            provenance,
            expected_hash,
        )
    } else {
        NonosAttestationCircuit::<Fr>::new(
            capsule_commitment,
            program_hash,
            pcr_preimage,
            hardware_attestation,
        )
    };

    let seed_hash = blake3::hash(args.seed.as_bytes());
    let seed_u64 = u64::from_le_bytes(seed_hash.as_bytes()[..8].try_into().unwrap());
    let mut rng = StdRng::seed_from_u64(seed_u64);

    println!("Generating Groth16 proof...");
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng)
        .map_err(|e| format!("Proof generation failed: {e}"))?;

    let mut proof_bytes = Vec::new();
    proof.serialize_with_mode(&mut proof_bytes, Compress::Yes)
        .map_err(|e| format!("Failed to serialize proof: {e}"))?;

    println!("  Proof generated ({} bytes)", proof_bytes.len());

    if proof_bytes.len() != 192 {
        return Err(format!("Unexpected proof size: {} (expected 192)", proof_bytes.len()));
    }

    fs::write(&args.output, &proof_bytes)
        .map_err(|e| format!("Failed to write proof: {e}"))?;
    println!("  Proof written to: {}", args.output.display());

    let circuit_for_inputs = if let Some(ref provenance_path) = args.provenance {
        let provenance_bytes = fs::read(provenance_path)
            .map_err(|e| format!("Failed to read provenance file: {e}"))?;

        let mut prov_data = [0u8; 128];
        prov_data.copy_from_slice(&provenance_bytes[..128]);
        let provenance = BuildProvenance::from_bytes(&prov_data);

        let mut expected_hash = [0u8; 32];
        expected_hash.copy_from_slice(&provenance_bytes[128..160]);

        NonosAttestationCircuit::<Fr>::with_build_provenance(
            capsule_commitment,
            program_hash,
            pcr_preimage,
            hardware_attestation,
            provenance,
            expected_hash,
        )
    } else {
        NonosAttestationCircuit::<Fr>::new(
            capsule_commitment,
            program_hash,
            pcr_preimage,
            hardware_attestation,
        )
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit_for_inputs.generate_constraints(cs.clone())
        .map_err(|e| format!("Failed to synthesize circuit for public inputs: {e}"))?;

    let public_input_field_elements: Vec<Fr> = cs.borrow()
        .ok_or("Failed to borrow constraint system")?
        .instance_assignment
        .iter()
        .skip(1)
        .cloned()
        .collect();

    println!("  Public inputs extracted: {} field elements", public_input_field_elements.len());

    if let Some(ref pi_path) = args.public_inputs_out {
        let mut public_inputs_bytes = Vec::with_capacity(public_input_field_elements.len() * 32);
        for fe in &public_input_field_elements {
            let bytes = fe.into_bigint().to_bytes_be();
            let padding = 32 - bytes.len();
            public_inputs_bytes.extend(core::iter::repeat(0u8).take(padding));
            public_inputs_bytes.extend_from_slice(&bytes);
        }

        fs::write(pi_path, &public_inputs_bytes)
            .map_err(|e| format!("Failed to write public inputs: {e}"))?;
        println!("  Public inputs written to: {} ({} bytes)", pi_path.display(), public_inputs_bytes.len());
    }

    println!();
    println!("=== Proof Generation Complete ===");
    println!("Program hash:       {}", hex::encode(&program_hash[..8]));
    println!("Capsule commitment: {}", hex::encode(&capsule_commitment[..8]));
    println!("Proof size:         {} bytes", proof_bytes.len());

    if args.verbose {
        println!();
        println!("Full program hash: {}", hex::encode(&program_hash));
        println!("Full commitment:   {}", hex::encode(&capsule_commitment));
    }

    Ok(())
}
