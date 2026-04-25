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

extern crate alloc;
use super::error::{DnssecError, DnssecResult};
use super::types::{DnskeyRecord, DnssecAlgorithm, RrsigRecord};
use alloc::string::String;
use alloc::vec::Vec;

pub fn parse_rrsig(data: &[u8]) -> DnssecResult<RrsigRecord> {
    if data.len() < 18 {
        return Err(DnssecError::ParseError);
    }
    let type_covered = u16::from_be_bytes([data[0], data[1]]);
    let algorithm = DnssecAlgorithm::from_u8(data[2]).ok_or(DnssecError::UnknownAlgorithm)?;
    let labels = data[3];
    let original_ttl = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let expiration = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let inception = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    let key_tag = u16::from_be_bytes([data[16], data[17]]);
    let (signer_name, sig_start) = parse_dns_name(&data[18..])?;
    let signature = data[18 + sig_start..].to_vec();
    Ok(RrsigRecord {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        expiration,
        inception,
        key_tag,
        signer_name,
        signature,
    })
}

fn parse_dns_name(data: &[u8]) -> DnssecResult<(String, usize)> {
    let mut name = String::new();
    let mut pos = 0;
    while pos < data.len() && data[pos] != 0 {
        let len = data[pos] as usize;
        pos += 1;
        if pos + len > data.len() {
            return Err(DnssecError::ParseError);
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(
            core::str::from_utf8(&data[pos..pos + len]).map_err(|_| DnssecError::ParseError)?,
        );
        pos += len;
    }
    Ok((name, pos + 1))
}

pub fn build_rrset_data(rrsig: &RrsigRecord, owner: &[u8], rrset: &[Vec<u8>]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&rrsig.type_covered.to_be_bytes());
    data.push(rrsig.algorithm as u8);
    data.push(rrsig.labels);
    data.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
    data.extend_from_slice(&rrsig.expiration.to_be_bytes());
    data.extend_from_slice(&rrsig.inception.to_be_bytes());
    data.extend_from_slice(&rrsig.key_tag.to_be_bytes());
    data.extend_from_slice(owner);
    for rr in rrset {
        data.extend_from_slice(rr);
    }
    data
}

pub fn verify_rrsig(rrsig: &RrsigRecord, dnskey: &DnskeyRecord, data: &[u8]) -> DnssecResult<bool> {
    if rrsig.key_tag != dnskey.key_tag {
        return Err(DnssecError::InvalidKeyTag);
    }
    if rrsig.algorithm != dnskey.algorithm {
        return Err(DnssecError::UnsupportedAlgorithm);
    }
    match dnskey.algorithm {
        DnssecAlgorithm::RsaSha256 => verify_rsa_sha256(data, &rrsig.signature, &dnskey.public_key),
        DnssecAlgorithm::EcdsaP256Sha256 => {
            verify_ecdsa_p256(data, &rrsig.signature, &dnskey.public_key)
        }
        DnssecAlgorithm::Ed25519 => verify_ed25519(data, &rrsig.signature, &dnskey.public_key),
        _ => Err(DnssecError::UnsupportedAlgorithm),
    }
}

fn verify_rsa_sha256(data: &[u8], sig: &[u8], pubkey: &[u8]) -> DnssecResult<bool> {
    if pubkey.is_empty() {
        return Err(DnssecError::InvalidSignature);
    }
    let (e_bytes, n_bytes) = parse_dnskey_rsa(pubkey)?;
    let rsa_key = crate::crypto::asymmetric::rsa::create_public_key(n_bytes, e_bytes);
    Ok(crate::crypto::asymmetric::rsa::verify_pkcs1v15(&rsa_key, data, sig))
}

fn parse_dnskey_rsa(pubkey: &[u8]) -> DnssecResult<(Vec<u8>, Vec<u8>)> {
    let exp_len = if pubkey[0] == 0 {
        if pubkey.len() < 3 {
            return Err(DnssecError::ParseError);
        }
        ((pubkey[1] as usize) << 8) | (pubkey[2] as usize)
    } else {
        pubkey[0] as usize
    };
    let exp_start = if pubkey[0] == 0 { 3 } else { 1 };
    if exp_start + exp_len > pubkey.len() {
        return Err(DnssecError::ParseError);
    }
    let e = pubkey[exp_start..exp_start + exp_len].to_vec();
    let n = pubkey[exp_start + exp_len..].to_vec();
    Ok((e, n))
}

fn verify_ecdsa_p256(data: &[u8], sig: &[u8], pubkey: &[u8]) -> DnssecResult<bool> {
    let hash = crate::crypto::hash::sha256(data);
    let mut pk = [0u8; 65];
    pk[0] = 0x04;
    if pubkey.len() != 64 {
        return Err(DnssecError::InvalidSignature);
    }
    pk[1..].copy_from_slice(pubkey);
    let signature: [u8; 64] = sig.try_into().map_err(|_| DnssecError::InvalidSignature)?;
    Ok(crate::crypto::asymmetric::p256::verify(&pk, &hash, &signature))
}

fn verify_ed25519(data: &[u8], sig: &[u8], pubkey: &[u8]) -> DnssecResult<bool> {
    let pk: [u8; 32] = pubkey.try_into().map_err(|_| DnssecError::InvalidSignature)?;
    if sig.len() != 64 {
        return Err(DnssecError::InvalidSignature);
    }
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    s.copy_from_slice(&sig[32..]);
    let ed_sig = crate::crypto::asymmetric::ed25519::Signature { R: r, S: s };
    Ok(crate::crypto::asymmetric::ed25519::verify(&pk, data, &ed_sig))
}
