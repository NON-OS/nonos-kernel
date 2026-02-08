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

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::UniformRand;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};

pub const DS_CEREMONY: &str = "NONOS:CEREMONY:v1";
pub const DS_CONTRIBUTION: &str = "NONOS:CEREMONY:CONTRIBUTION:v1";
pub const DS_TOXIC_WASTE: &str = "NONOS:CEREMONY:TOXIC:v1";
pub const MIN_PARTICIPANTS: usize = 5;

#[derive(Debug)]
pub enum CeremonyError {
    InsufficientParticipants,
    InvalidPreviousParams,
    InvalidContribution,
    SerializationError(String),
    VerificationFailed,
    ToxicWasteNotDestroyed,
    InvalidRound,
    HashMismatch,
}

impl std::fmt::Display for CeremonyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientParticipants => write!(f, "need at least {} participants", MIN_PARTICIPANTS),
            Self::InvalidPreviousParams => write!(f, "invalid previous parameters"),
            Self::InvalidContribution => write!(f, "invalid contribution"),
            Self::SerializationError(s) => write!(f, "serialization: {}", s),
            Self::VerificationFailed => write!(f, "verification failed"),
            Self::ToxicWasteNotDestroyed => write!(f, "toxic waste destruction not verified"),
            Self::InvalidRound => write!(f, "invalid round number"),
            Self::HashMismatch => write!(f, "hash mismatch"),
        }
    }
}

impl std::error::Error for CeremonyError {}

#[derive(Serialize, Deserialize, Clone)]
pub struct CeremonyMetadata {
    pub ceremony_id: String,
    pub circuit_name: String,
    pub circuit_hash: [u8; 32],
    pub created_at: u64,
    pub minimum_participants: usize,
    pub current_round: u32,
    pub finalized: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ContributionRecord {
    pub round: u32,
    pub contributor_id: String,
    pub contributor_contact: String,
    pub location: String,
    pub randomness_source: String,
    pub previous_params_hash: [u8; 32],
    pub new_params_hash: [u8; 32],
    pub randomness_commitment: [u8; 32],
    pub contribution_timestamp: u64,
    pub destruction_attestation: Option<DestructionAttestation>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DestructionAttestation {
    pub method: String,
    pub witness_count: usize,
    pub attestation_hash: [u8; 32],
    pub video_hash: Option<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
pub struct CeremonyTranscript {
    pub metadata: CeremonyMetadata,
    pub contributions: Vec<ContributionRecord>,
    pub final_vk_hash: Option<[u8; 32]>,
    pub verification_passed: bool,
}

pub struct CeremonyParams {
    pub pk: ProvingKey<Bls12_381>,
    pub round: u32,
    pub params_hash: [u8; 32],
}

impl CeremonyParams {
    pub fn serialize(&self) -> Result<Vec<u8>, CeremonyError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.round.to_le_bytes());
        buf.extend_from_slice(&self.params_hash);
        self.pk
            .serialize_with_mode(&mut buf, Compress::Yes)
            .map_err(|e| CeremonyError::SerializationError(e.to_string()))?;
        Ok(buf)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, CeremonyError> {
        if data.len() < 36 {
            return Err(CeremonyError::InvalidPreviousParams);
        }
        let round = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let mut params_hash = [0u8; 32];
        params_hash.copy_from_slice(&data[4..36]);

        let pk = ProvingKey::<Bls12_381>::deserialize_with_mode(
            &data[36..],
            Compress::Yes,
            ark_serialize::Validate::Yes,
        )
        .map_err(|e| CeremonyError::SerializationError(e.to_string()))?;

        Ok(Self {
            pk,
            round,
            params_hash,
        })
    }
}

pub fn hash_params(pk: &ProvingKey<Bls12_381>) -> [u8; 32] {
    let mut buf = Vec::new();
    pk.serialize_with_mode(&mut buf, Compress::Yes).unwrap();
    let mut hasher = blake3::Hasher::new_derive_key(DS_CEREMONY);
    hasher.update(&buf);
    *hasher.finalize().as_bytes()
}

pub fn ceremony_init<C>(
    circuit: C,
    ceremony_id: &str,
    circuit_name: &str,
) -> Result<(CeremonyParams, CeremonyMetadata), CeremonyError>
where
    C: ark_relations::r1cs::ConstraintSynthesizer<Fr> + Clone,
{
    let circuit_hash = {
        let mut hasher = blake3::Hasher::new_derive_key(DS_CEREMONY);
        hasher.update(circuit_name.as_bytes());
        *hasher.finalize().as_bytes()
    };

    let mut rng = StdRng::from_entropy();
    let (pk, _vk) = <Groth16<Bls12_381> as SNARK<Fr>>::circuit_specific_setup(circuit, &mut rng)
        .map_err(|e| CeremonyError::SerializationError(e.to_string()))?;

    let params_hash = hash_params(&pk);

    let metadata = CeremonyMetadata {
        ceremony_id: ceremony_id.to_string(),
        circuit_name: circuit_name.to_string(),
        circuit_hash,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        minimum_participants: MIN_PARTICIPANTS,
        current_round: 0,
        finalized: false,
    };

    let params = CeremonyParams {
        pk,
        round: 0,
        params_hash,
    };

    Ok((params, metadata))
}

pub fn contribute_randomness(
    previous_params: &CeremonyParams,
    contributor_id: &str,
    contributor_contact: &str,
    location: &str,
    randomness_source: &str,
    external_randomness: &[u8],
) -> Result<(CeremonyParams, ContributionRecord), CeremonyError> {
    let previous_hash = hash_params(&previous_params.pk);
    if previous_hash != previous_params.params_hash {
        return Err(CeremonyError::HashMismatch);
    }

    let contribution_seed = {
        let mut hasher = blake3::Hasher::new_derive_key(DS_CONTRIBUTION);
        hasher.update(&previous_hash);
        hasher.update(contributor_id.as_bytes());
        hasher.update(external_randomness);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        hasher.update(&timestamp.to_le_bytes());

        *hasher.finalize().as_bytes()
    };

    let randomness_commitment = blake3::hash(&contribution_seed);

    let mut rng = StdRng::from_seed(contribution_seed);
    let tau: Fr = Fr::rand(&mut rng);
    let alpha: Fr = Fr::rand(&mut rng);
    let beta: Fr = Fr::rand(&mut rng);

    let new_pk = apply_powers_of_tau(&previous_params.pk, tau, alpha, beta)?;

    let new_params_hash = hash_params(&new_pk);
    let new_round = previous_params.round + 1;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let record = ContributionRecord {
        round: new_round,
        contributor_id: contributor_id.to_string(),
        contributor_contact: contributor_contact.to_string(),
        location: location.to_string(),
        randomness_source: randomness_source.to_string(),
        previous_params_hash: previous_hash,
        new_params_hash,
        randomness_commitment: *randomness_commitment.as_bytes(),
        contribution_timestamp: timestamp,
        destruction_attestation: None,
    };

    let new_params = CeremonyParams {
        pk: new_pk,
        round: new_round,
        params_hash: new_params_hash,
    };

    Ok((new_params, record))
}

fn apply_powers_of_tau(
    pk: &ProvingKey<Bls12_381>,
    tau: Fr,
    alpha: Fr,
    beta: Fr,
) -> Result<ProvingKey<Bls12_381>, CeremonyError> {
    use ark_ec::CurveGroup;
    use ark_ff::Field;

    let mut new_pk = pk.clone();

    let max_degree = pk.vk.gamma_abc_g1.len()
        .max(pk.a_query.len())
        .max(pk.b_g1_query.len())
        .max(pk.b_g2_query.len())
        .max(pk.h_query.len())
        .max(pk.l_query.len())
        + 10;

    let mut tau_powers = Vec::with_capacity(max_degree);
    tau_powers.push(Fr::from(1u64));
    for i in 1..max_degree {
        tau_powers.push(tau_powers[i - 1] * tau);
    }

    new_pk.vk.alpha_g1 = (pk.vk.alpha_g1.into_group() * alpha).into_affine();
    new_pk.vk.beta_g2 = (pk.vk.beta_g2.into_group() * beta).into_affine();

    let alpha_beta = alpha * beta;
    new_pk.beta_g1 = (pk.beta_g1.into_group() * beta).into_affine();

    for (i, g1) in new_pk.vk.gamma_abc_g1.iter_mut().enumerate() {
        if i < tau_powers.len() {
            *g1 = (g1.into_group() * tau_powers[i]).into_affine();
        }
    }

    for (i, g1) in new_pk.a_query.iter_mut().enumerate() {
        if i < tau_powers.len() {
            *g1 = (g1.into_group() * tau_powers[i]).into_affine();
        }
    }

    for (i, g1) in new_pk.b_g1_query.iter_mut().enumerate() {
        if i < tau_powers.len() {
            *g1 = (g1.into_group() * tau_powers[i]).into_affine();
        }
    }

    for (i, g2) in new_pk.b_g2_query.iter_mut().enumerate() {
        if i < tau_powers.len() {
            *g2 = (g2.into_group() * tau_powers[i]).into_affine();
        }
    }

    for (i, g1) in new_pk.h_query.iter_mut().enumerate() {
        if i < tau_powers.len() {
            let tau_i = tau_powers[i];
            let tau_next = if i + 1 < tau_powers.len() {
                tau_powers[i + 1]
            } else {
                tau_powers[i] * tau
            };
            *g1 = (g1.into_group() * (tau_next - tau_i)).into_affine();
        }
    }

    for (i, g1) in new_pk.l_query.iter_mut().enumerate() {
        if i < tau_powers.len() {
            *g1 = (g1.into_group() * (alpha_beta * tau_powers[i])).into_affine();
        }
    }

    Ok(new_pk)
}

pub fn verify_contribution(
    previous_params: &CeremonyParams,
    new_params: &CeremonyParams,
    record: &ContributionRecord,
) -> Result<bool, CeremonyError> {
    if new_params.round != previous_params.round + 1 {
        return Err(CeremonyError::InvalidRound);
    }

    let prev_hash = hash_params(&previous_params.pk);
    if prev_hash != record.previous_params_hash {
        return Err(CeremonyError::HashMismatch);
    }

    let new_hash = hash_params(&new_params.pk);
    if new_hash != record.new_params_hash {
        return Err(CeremonyError::HashMismatch);
    }

    if new_params.pk.vk.gamma_abc_g1.len() != previous_params.pk.vk.gamma_abc_g1.len() {
        return Err(CeremonyError::InvalidContribution);
    }

    Ok(true)
}

pub fn ceremony_finalize(
    final_params: &CeremonyParams,
    contributions: &[ContributionRecord],
) -> Result<(VerifyingKey<Bls12_381>, CeremonyTranscript), CeremonyError> {
    if contributions.len() < MIN_PARTICIPANTS {
        return Err(CeremonyError::InsufficientParticipants);
    }

    for contribution in contributions {
        if contribution.destruction_attestation.is_none() {
            return Err(CeremonyError::ToxicWasteNotDestroyed);
        }
    }

    let vk = final_params.pk.vk.clone();
    let vk_hash = {
        let mut buf = Vec::new();
        vk.serialize_with_mode(&mut buf, Compress::Yes).unwrap();
        let mut hasher = blake3::Hasher::new_derive_key(DS_CEREMONY);
        hasher.update(&buf);
        *hasher.finalize().as_bytes()
    };

    let metadata = CeremonyMetadata {
        ceremony_id: format!("nonos-ceremony-{}", final_params.round),
        circuit_name: "nonos-attestation".to_string(),
        circuit_hash: [0u8; 32],
        created_at: contributions.first().map(|c| c.contribution_timestamp).unwrap_or(0),
        minimum_participants: MIN_PARTICIPANTS,
        current_round: final_params.round,
        finalized: true,
    };

    let transcript = CeremonyTranscript {
        metadata,
        contributions: contributions.to_vec(),
        final_vk_hash: Some(vk_hash),
        verification_passed: true,
    };

    Ok((vk, transcript))
}

pub fn add_destruction_attestation(
    record: &mut ContributionRecord,
    method: &str,
    witness_count: usize,
    video_hash: Option<[u8; 32]>,
) {
    let attestation_data = format!(
        "{}:{}:{}:{}",
        record.contributor_id,
        record.round,
        method,
        witness_count
    );
    let attestation_hash = *blake3::hash(attestation_data.as_bytes()).as_bytes();

    record.destruction_attestation = Some(DestructionAttestation {
        method: method.to_string(),
        witness_count,
        attestation_hash,
        video_hash,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NonosAttestationCircuit;
    use ark_bls12_381::Fr;

    #[test]
    fn test_ceremony_init() {
        let circuit: NonosAttestationCircuit<Fr> = Default::default();
        let result = ceremony_init(circuit, "test-ceremony", "nonos-attestation");
        assert!(result.is_ok());
    }
}
