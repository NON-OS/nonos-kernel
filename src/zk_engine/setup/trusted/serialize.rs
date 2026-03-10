// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

use alloc::vec::Vec;
use crate::zk_engine::groth16::{FieldElement, G1Point, G2Point, G2FieldElement, ProvingKey, VerifyingKey};
use crate::zk_engine::ZKError;
use crate::zk_engine::setup::params::SetupParameters;

pub(super) fn load_from_storage(path: &str) -> Result<SetupParameters, ZKError> {
    use crate::fs::nonos_filesystem::NonosFilesystem;

    let fs = NonosFilesystem::new();
    let data = fs.read_file(path).map_err(|_| ZKError::TrustedSetupNotFound)?;

    if data.len() < 16 {
        return Err(ZKError::InvalidFormat);
    }

    if &data[0..4] != b"NZKS" {
        return Err(ZKError::InvalidFormat);
    }

    let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if version != 1 {
        return Err(ZKError::InvalidFormat);
    }

    deserialize_params(&data[8..])
}

pub(super) fn save_to_storage(path: &str, params: &SetupParameters) -> Result<(), ZKError> {
    use crate::fs::nonos_filesystem::NonosFilesystem;

    let mut data = Vec::new();
    data.extend_from_slice(b"NZKS");
    data.extend_from_slice(&1u32.to_le_bytes());
    serialize_params(params, &mut data);

    let fs = NonosFilesystem::new();
    fs.create_file(path, &data).map_err(|_| ZKError::SetupError)?;
    Ok(())
}

fn serialize_params(params: &SetupParameters, out: &mut Vec<u8>) {
    let pk = &params.proving_key;
    out.extend_from_slice(&(pk.num_variables as u32).to_le_bytes());
    out.extend_from_slice(&(pk.num_inputs as u32).to_le_bytes());

    serialize_g1(&pk.alpha_g1, out);
    serialize_g1(&pk.beta_g1, out);
    serialize_g1(&pk.delta_g1, out);
    serialize_g2(&pk.beta_g2, out);
    serialize_g2(&pk.delta_g2, out);

    out.extend_from_slice(&(pk.a_query.len() as u32).to_le_bytes());
    for pt in &pk.a_query { serialize_g1(pt, out); }

    out.extend_from_slice(&(pk.b_g1_query.len() as u32).to_le_bytes());
    for pt in &pk.b_g1_query { serialize_g1(pt, out); }

    out.extend_from_slice(&(pk.b_g2_query.len() as u32).to_le_bytes());
    for pt in &pk.b_g2_query { serialize_g2(pt, out); }

    out.extend_from_slice(&(pk.h_query.len() as u32).to_le_bytes());
    for pt in &pk.h_query { serialize_g1(pt, out); }

    out.extend_from_slice(&(pk.l_query.len() as u32).to_le_bytes());
    for pt in &pk.l_query { serialize_g1(pt, out); }

    let vk = &params.verifying_key;
    serialize_g1(&vk.alpha_g1, out);
    serialize_g2(&vk.beta_g2, out);
    serialize_g2(&vk.gamma_g2, out);
    serialize_g2(&vk.delta_g2, out);

    out.extend_from_slice(&(vk.ic.len() as u32).to_le_bytes());
    for pt in &vk.ic { serialize_g1(pt, out); }
}

fn deserialize_params(data: &[u8]) -> Result<SetupParameters, ZKError> {
    if data.len() < 8 { return Err(ZKError::InvalidFormat); }

    let mut offset = 0;

    let num_variables = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]) as usize;
    offset += 4;
    let num_inputs = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]) as usize;
    offset += 4;

    let (alpha_g1, o) = deserialize_g1(data, offset)?; offset = o;
    let (beta_g1, o) = deserialize_g1(data, offset)?; offset = o;
    let (delta_g1, o) = deserialize_g1(data, offset)?; offset = o;
    let (beta_g2, o) = deserialize_g2(data, offset)?; offset = o;
    let (delta_g2, o) = deserialize_g2(data, offset)?; offset = o;

    let (a_query, o) = deserialize_g1_vec(data, offset)?; offset = o;
    let (b_g1_query, o) = deserialize_g1_vec(data, offset)?; offset = o;
    let (b_g2_query, o) = deserialize_g2_vec(data, offset)?; offset = o;
    let (h_query, o) = deserialize_g1_vec(data, offset)?; offset = o;
    let (l_query, o) = deserialize_g1_vec(data, offset)?; offset = o;

    let proving_key = ProvingKey {
        alpha_g1, beta_g1, beta_g2, delta_g1, delta_g2,
        a_query, b_g1_query, b_g2_query, h_query, l_query,
        num_variables, num_inputs,
    };

    let (vk_alpha_g1, o) = deserialize_g1(data, offset)?; offset = o;
    let (vk_beta_g2, o) = deserialize_g2(data, offset)?; offset = o;
    let (vk_gamma_g2, o) = deserialize_g2(data, offset)?; offset = o;
    let (vk_delta_g2, o) = deserialize_g2(data, offset)?; offset = o;
    let (ic, _) = deserialize_g1_vec(data, offset)?;

    let verifying_key = VerifyingKey {
        alpha_g1: vk_alpha_g1,
        beta_g2: vk_beta_g2,
        gamma_g2: vk_gamma_g2,
        delta_g2: vk_delta_g2,
        ic,
    };

    Ok(SetupParameters { proving_key, verifying_key, toxic_waste: None })
}

fn u64_limbs_to_bytes(limbs: &[u64; 4]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, &limb) in limbs.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

fn bytes_to_u64_limbs(bytes: &[u8; 32]) -> [u64; 4] {
    [
        u64::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]),
        u64::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]]),
        u64::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23]]),
        u64::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31]]),
    ]
}

fn serialize_g1(pt: &G1Point, out: &mut Vec<u8>) {
    out.extend_from_slice(&u64_limbs_to_bytes(&pt.x.limbs));
    out.extend_from_slice(&u64_limbs_to_bytes(&pt.y.limbs));
}

fn serialize_g2(pt: &G2Point, out: &mut Vec<u8>) {
    out.extend_from_slice(&u64_limbs_to_bytes(&pt.x.c0.limbs));
    out.extend_from_slice(&u64_limbs_to_bytes(&pt.x.c1.limbs));
    out.extend_from_slice(&u64_limbs_to_bytes(&pt.y.c0.limbs));
    out.extend_from_slice(&u64_limbs_to_bytes(&pt.y.c1.limbs));
}

fn deserialize_g1(data: &[u8], offset: usize) -> Result<(G1Point, usize), ZKError> {
    if offset + 64 > data.len() { return Err(ZKError::InvalidFormat); }

    let mut x_bytes = [0u8; 32];
    let mut y_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&data[offset..offset + 32]);
    y_bytes.copy_from_slice(&data[offset + 32..offset + 64]);

    Ok((G1Point {
        x: FieldElement { limbs: bytes_to_u64_limbs(&x_bytes) },
        y: FieldElement { limbs: bytes_to_u64_limbs(&y_bytes) },
        z: FieldElement::one(),
    }, offset + 64))
}

fn deserialize_g2(data: &[u8], offset: usize) -> Result<(G2Point, usize), ZKError> {
    if offset + 128 > data.len() { return Err(ZKError::InvalidFormat); }

    let mut c0_x = [0u8; 32];
    let mut c1_x = [0u8; 32];
    let mut c0_y = [0u8; 32];
    let mut c1_y = [0u8; 32];

    c0_x.copy_from_slice(&data[offset..offset + 32]);
    c1_x.copy_from_slice(&data[offset + 32..offset + 64]);
    c0_y.copy_from_slice(&data[offset + 64..offset + 96]);
    c1_y.copy_from_slice(&data[offset + 96..offset + 128]);

    Ok((G2Point {
        x: G2FieldElement {
            c0: FieldElement { limbs: bytes_to_u64_limbs(&c0_x) },
            c1: FieldElement { limbs: bytes_to_u64_limbs(&c1_x) },
        },
        y: G2FieldElement {
            c0: FieldElement { limbs: bytes_to_u64_limbs(&c0_y) },
            c1: FieldElement { limbs: bytes_to_u64_limbs(&c1_y) },
        },
        z: G2FieldElement::one(),
    }, offset + 128))
}

fn deserialize_g1_vec(data: &[u8], offset: usize) -> Result<(Vec<G1Point>, usize), ZKError> {
    if offset + 4 > data.len() { return Err(ZKError::InvalidFormat); }

    let count = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]) as usize;
    let mut current = offset + 4;

    let mut points = Vec::with_capacity(count);
    for _ in 0..count {
        let (pt, new_offset) = deserialize_g1(data, current)?;
        points.push(pt);
        current = new_offset;
    }

    Ok((points, current))
}

fn deserialize_g2_vec(data: &[u8], offset: usize) -> Result<(Vec<G2Point>, usize), ZKError> {
    if offset + 4 > data.len() { return Err(ZKError::InvalidFormat); }

    let count = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]) as usize;
    let mut current = offset + 4;

    let mut points = Vec::with_capacity(count);
    for _ in 0..count {
        let (pt, new_offset) = deserialize_g2(data, current)?;
        points.push(pt);
        current = new_offset;
    }

    Ok((points, current))
}
