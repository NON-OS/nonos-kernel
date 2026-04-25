// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use super::rlp::{
    encode_access_list, rlp_encode_bytes, rlp_encode_list, rlp_encode_u128, rlp_encode_u64,
};
use super::types::{SignedTransaction, TransactionRequest, TransactionType};
use crate::crypto::asymmetric::secp256k1::{
    recover_public_key, sign_recoverable, RecoverableSignature,
};
use crate::crypto::hash::keccak256;
use crate::crypto::{CryptoError, CryptoResult};
use alloc::vec::Vec;

pub fn build_transaction(
    to: &[u8; 20],
    value: u128,
    data: Vec<u8>,
    nonce: u64,
    gas_limit: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    chain_id: u64,
) -> TransactionRequest {
    TransactionRequest::new_eip1559(chain_id)
        .with_to(*to)
        .with_value(value)
        .with_data(data)
        .with_nonce(nonce)
        .with_gas_limit(gas_limit)
        .with_eip1559_fees(max_fee_per_gas, max_priority_fee_per_gas)
}

pub fn sign_transaction(
    tx: &TransactionRequest,
    secret_key: &[u8; 32],
) -> CryptoResult<SignedTransaction> {
    match tx.tx_type {
        TransactionType::Legacy => sign_legacy(tx, secret_key),
        TransactionType::Eip1559 => sign_eip1559(tx, secret_key),
        TransactionType::Eip2930 => sign_eip2930(tx, secret_key),
    }
}

fn sign_legacy(tx: &TransactionRequest, secret_key: &[u8; 32]) -> CryptoResult<SignedTransaction> {
    let mut items = vec![
        rlp_encode_u64(tx.nonce),
        rlp_encode_u128(tx.gas_price.unwrap_or(0)),
        rlp_encode_u64(tx.gas_limit),
    ];
    items.push(tx.to.map_or_else(|| rlp_encode_bytes(&[]), |to| rlp_encode_bytes(&to)));
    items.extend([
        rlp_encode_u128(tx.value),
        rlp_encode_bytes(&tx.data),
        rlp_encode_u64(tx.chain_id),
        rlp_encode_bytes(&[]),
        rlp_encode_bytes(&[]),
    ]);
    let hash = keccak256(&rlp_encode_list(&items));
    let sig = sign_recoverable(secret_key, &hash).ok_or(CryptoError::SigError)?;
    let v = (sig.recovery_id as u64) + 35 + tx.chain_id * 2;
    let mut signed = vec![
        rlp_encode_u64(tx.nonce),
        rlp_encode_u128(tx.gas_price.unwrap_or(0)),
        rlp_encode_u64(tx.gas_limit),
    ];
    signed.push(tx.to.map_or_else(|| rlp_encode_bytes(&[]), |to| rlp_encode_bytes(&to)));
    signed.extend([
        rlp_encode_u128(tx.value),
        rlp_encode_bytes(&tx.data),
        rlp_encode_u64(v),
        rlp_encode_bytes(&sig.r),
        rlp_encode_bytes(&sig.s),
    ]);
    let raw = rlp_encode_list(&signed);
    Ok(SignedTransaction { hash: keccak256(&raw), from: recover_sender(&hash, &sig)?, raw })
}

fn sign_eip1559(tx: &TransactionRequest, secret_key: &[u8; 32]) -> CryptoResult<SignedTransaction> {
    let mut items = vec![
        rlp_encode_u64(tx.chain_id),
        rlp_encode_u64(tx.nonce),
        rlp_encode_u128(tx.max_priority_fee_per_gas.unwrap_or(0)),
        rlp_encode_u128(tx.max_fee_per_gas.unwrap_or(0)),
        rlp_encode_u64(tx.gas_limit),
    ];
    items.push(tx.to.map_or_else(|| rlp_encode_bytes(&[]), |to| rlp_encode_bytes(&to)));
    items.extend([
        rlp_encode_u128(tx.value),
        rlp_encode_bytes(&tx.data),
        encode_access_list(&tx.access_list),
    ]);
    let payload = rlp_encode_list(&items);
    let mut unsigned = Vec::with_capacity(1 + payload.len());
    unsigned.push(0x02);
    unsigned.extend_from_slice(&payload);
    let hash = keccak256(&unsigned);
    let sig = sign_recoverable(secret_key, &hash).ok_or(CryptoError::SigError)?;
    items.extend([
        rlp_encode_u64(sig.recovery_id as u64),
        rlp_encode_bytes(&sig.r),
        rlp_encode_bytes(&sig.s),
    ]);
    let signed_payload = rlp_encode_list(&items);
    let mut raw = Vec::with_capacity(1 + signed_payload.len());
    raw.push(0x02);
    raw.extend_from_slice(&signed_payload);
    Ok(SignedTransaction { hash: keccak256(&raw), from: recover_sender(&hash, &sig)?, raw })
}

fn sign_eip2930(tx: &TransactionRequest, secret_key: &[u8; 32]) -> CryptoResult<SignedTransaction> {
    let mut items = vec![
        rlp_encode_u64(tx.chain_id),
        rlp_encode_u64(tx.nonce),
        rlp_encode_u128(tx.gas_price.unwrap_or(0)),
        rlp_encode_u64(tx.gas_limit),
    ];
    items.push(tx.to.map_or_else(|| rlp_encode_bytes(&[]), |to| rlp_encode_bytes(&to)));
    items.extend([
        rlp_encode_u128(tx.value),
        rlp_encode_bytes(&tx.data),
        encode_access_list(&tx.access_list),
    ]);
    let payload = rlp_encode_list(&items);
    let mut unsigned = Vec::with_capacity(1 + payload.len());
    unsigned.push(0x01);
    unsigned.extend_from_slice(&payload);
    let hash = keccak256(&unsigned);
    let sig = sign_recoverable(secret_key, &hash).ok_or(CryptoError::SigError)?;
    items.extend([
        rlp_encode_u64(sig.recovery_id as u64),
        rlp_encode_bytes(&sig.r),
        rlp_encode_bytes(&sig.s),
    ]);
    let signed_payload = rlp_encode_list(&items);
    let mut raw = Vec::with_capacity(1 + signed_payload.len());
    raw.push(0x01);
    raw.extend_from_slice(&signed_payload);
    Ok(SignedTransaction { hash: keccak256(&raw), from: recover_sender(&hash, &sig)?, raw })
}

fn recover_sender(hash: &[u8; 32], sig: &RecoverableSignature) -> CryptoResult<[u8; 20]> {
    let pk = recover_public_key(hash, sig).ok_or(CryptoError::InvalidInput)?;
    let mut address = [0u8; 20];
    address.copy_from_slice(&keccak256(&pk[1..])[12..32]);
    Ok(address)
}
