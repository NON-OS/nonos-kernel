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

//! Ethereum transaction building and signing.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::crypto::asymmetric::secp256k1::{sign_recoverable, RecoverableSignature};
use crate::crypto::hash::keccak256;
use crate::crypto::{CryptoError, CryptoResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionType {
    Legacy,
    Eip2930,
    Eip1559,
}

#[derive(Debug, Clone)]
pub struct TransactionRequest {
    pub tx_type: TransactionType,
    pub chain_id: u64,
    pub nonce: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub gas_limit: u64,
    pub gas_price: Option<u128>,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
    pub access_list: Vec<AccessListItem>,
}

#[derive(Debug, Clone)]
pub struct AccessListItem {
    pub address: [u8; 20],
    pub storage_keys: Vec<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct SignedTransaction {
    pub raw: Vec<u8>,
    pub hash: [u8; 32],
    pub from: [u8; 20],
}

impl SignedTransaction {
    pub fn hash_hex(&self) -> String {
        let mut hex = String::with_capacity(66);
        hex.push_str("0x");
        for byte in &self.hash {
            hex.push_str(&alloc::format!("{:02x}", byte));
        }
        hex
    }

    pub fn raw_hex(&self) -> String {
        let mut hex = String::with_capacity(self.raw.len() * 2 + 2);
        hex.push_str("0x");
        for byte in &self.raw {
            hex.push_str(&alloc::format!("{:02x}", byte));
        }
        hex
    }
}

impl TransactionRequest {
    pub fn new_legacy(chain_id: u64) -> Self {
        Self {
            tx_type: TransactionType::Legacy,
            chain_id,
            nonce: 0,
            to: None,
            value: 0,
            data: Vec::new(),
            gas_limit: 21000,
            gas_price: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: Vec::new(),
        }
    }

    pub fn new_eip1559(chain_id: u64) -> Self {
        Self {
            tx_type: TransactionType::Eip1559,
            chain_id,
            nonce: 0,
            to: None,
            value: 0,
            data: Vec::new(),
            gas_limit: 21000,
            gas_price: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            access_list: Vec::new(),
        }
    }

    pub fn with_to(mut self, to: [u8; 20]) -> Self {
        self.to = Some(to);
        self
    }

    pub fn with_value(mut self, value: u128) -> Self {
        self.value = value;
        self
    }

    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    pub fn with_nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }

    pub fn with_gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
        self
    }

    pub fn with_gas_price(mut self, gas_price: u128) -> Self {
        self.gas_price = Some(gas_price);
        self
    }

    pub fn with_eip1559_fees(mut self, max_fee: u128, priority_fee: u128) -> Self {
        self.max_fee_per_gas = Some(max_fee);
        self.max_priority_fee_per_gas = Some(priority_fee);
        self
    }
}

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
        TransactionType::Legacy => sign_legacy_transaction(tx, secret_key),
        TransactionType::Eip1559 => sign_eip1559_transaction(tx, secret_key),
        TransactionType::Eip2930 => sign_eip2930_transaction(tx, secret_key),
    }
}

fn sign_legacy_transaction(
    tx: &TransactionRequest,
    secret_key: &[u8; 32],
) -> CryptoResult<SignedTransaction> {
    let mut items = Vec::new();

    items.push(rlp_encode_u64(tx.nonce));
    items.push(rlp_encode_u128(tx.gas_price.unwrap_or(0)));
    items.push(rlp_encode_u64(tx.gas_limit));

    match &tx.to {
        Some(to) => items.push(rlp_encode_bytes(to)),
        None => items.push(rlp_encode_bytes(&[])),
    }

    items.push(rlp_encode_u128(tx.value));
    items.push(rlp_encode_bytes(&tx.data));
    items.push(rlp_encode_u64(tx.chain_id));
    items.push(rlp_encode_bytes(&[]));
    items.push(rlp_encode_bytes(&[]));

    let unsigned = rlp_encode_list(&items);
    let hash = keccak256(&unsigned);

    let signature = sign_recoverable(secret_key, &hash).ok_or(CryptoError::SigError)?;
    let v = (signature.recovery_id as u64) + 35 + tx.chain_id * 2;

    let mut signed_items = Vec::new();
    signed_items.push(rlp_encode_u64(tx.nonce));
    signed_items.push(rlp_encode_u128(tx.gas_price.unwrap_or(0)));
    signed_items.push(rlp_encode_u64(tx.gas_limit));

    match &tx.to {
        Some(to) => signed_items.push(rlp_encode_bytes(to)),
        None => signed_items.push(rlp_encode_bytes(&[])),
    }

    signed_items.push(rlp_encode_u128(tx.value));
    signed_items.push(rlp_encode_bytes(&tx.data));
    signed_items.push(rlp_encode_u64(v));
    signed_items.push(rlp_encode_bytes(&signature.r));
    signed_items.push(rlp_encode_bytes(&signature.s));

    let raw = rlp_encode_list(&signed_items);
    let tx_hash = keccak256(&raw);

    let from = recover_sender(&hash, &signature)?;

    Ok(SignedTransaction {
        raw,
        hash: tx_hash,
        from,
    })
}

fn sign_eip1559_transaction(
    tx: &TransactionRequest,
    secret_key: &[u8; 32],
) -> CryptoResult<SignedTransaction> {
    let mut items = Vec::new();

    items.push(rlp_encode_u64(tx.chain_id));
    items.push(rlp_encode_u64(tx.nonce));
    items.push(rlp_encode_u128(tx.max_priority_fee_per_gas.unwrap_or(0)));
    items.push(rlp_encode_u128(tx.max_fee_per_gas.unwrap_or(0)));
    items.push(rlp_encode_u64(tx.gas_limit));

    match &tx.to {
        Some(to) => items.push(rlp_encode_bytes(to)),
        None => items.push(rlp_encode_bytes(&[])),
    }

    items.push(rlp_encode_u128(tx.value));
    items.push(rlp_encode_bytes(&tx.data));
    items.push(encode_access_list(&tx.access_list));

    let payload = rlp_encode_list(&items);
    let mut unsigned = Vec::with_capacity(1 + payload.len());
    unsigned.push(0x02);
    unsigned.extend_from_slice(&payload);

    let hash = keccak256(&unsigned);
    let signature = sign_recoverable(secret_key, &hash).ok_or(CryptoError::SigError)?;

    let mut signed_items = items.clone();
    signed_items.push(rlp_encode_u64(signature.recovery_id as u64));
    signed_items.push(rlp_encode_bytes(&signature.r));
    signed_items.push(rlp_encode_bytes(&signature.s));

    let signed_payload = rlp_encode_list(&signed_items);
    let mut raw = Vec::with_capacity(1 + signed_payload.len());
    raw.push(0x02);
    raw.extend_from_slice(&signed_payload);

    let tx_hash = keccak256(&raw);
    let from = recover_sender(&hash, &signature)?;

    Ok(SignedTransaction {
        raw,
        hash: tx_hash,
        from,
    })
}

fn sign_eip2930_transaction(
    tx: &TransactionRequest,
    secret_key: &[u8; 32],
) -> CryptoResult<SignedTransaction> {
    let mut items = Vec::new();

    items.push(rlp_encode_u64(tx.chain_id));
    items.push(rlp_encode_u64(tx.nonce));
    items.push(rlp_encode_u128(tx.gas_price.unwrap_or(0)));
    items.push(rlp_encode_u64(tx.gas_limit));

    match &tx.to {
        Some(to) => items.push(rlp_encode_bytes(to)),
        None => items.push(rlp_encode_bytes(&[])),
    }

    items.push(rlp_encode_u128(tx.value));
    items.push(rlp_encode_bytes(&tx.data));
    items.push(encode_access_list(&tx.access_list));

    let payload = rlp_encode_list(&items);
    let mut unsigned = Vec::with_capacity(1 + payload.len());
    unsigned.push(0x01);
    unsigned.extend_from_slice(&payload);

    let hash = keccak256(&unsigned);
    let signature = sign_recoverable(secret_key, &hash).ok_or(CryptoError::SigError)?;

    let mut signed_items = items.clone();
    signed_items.push(rlp_encode_u64(signature.recovery_id as u64));
    signed_items.push(rlp_encode_bytes(&signature.r));
    signed_items.push(rlp_encode_bytes(&signature.s));

    let signed_payload = rlp_encode_list(&signed_items);
    let mut raw = Vec::with_capacity(1 + signed_payload.len());
    raw.push(0x01);
    raw.extend_from_slice(&signed_payload);

    let tx_hash = keccak256(&raw);
    let from = recover_sender(&hash, &signature)?;

    Ok(SignedTransaction {
        raw,
        hash: tx_hash,
        from,
    })
}

fn recover_sender(hash: &[u8; 32], signature: &RecoverableSignature) -> CryptoResult<[u8; 20]> {
    use crate::crypto::asymmetric::secp256k1::recover_public_key;
    use crate::crypto::CryptoError;

    let public_key = recover_public_key(hash, signature)
        .ok_or(CryptoError::InvalidInput)?;
    let addr_hash = keccak256(&public_key[1..]);

    let mut address = [0u8; 20];
    address.copy_from_slice(&addr_hash[12..32]);

    Ok(address)
}

fn rlp_encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return alloc::vec![0x80];
    }
    if value < 128 {
        return alloc::vec![value as u8];
    }

    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    let significant = &bytes[start..];

    let mut result = Vec::with_capacity(1 + significant.len());
    result.push(0x80 + significant.len() as u8);
    result.extend_from_slice(significant);
    result
}

fn rlp_encode_u128(value: u128) -> Vec<u8> {
    if value == 0 {
        return alloc::vec![0x80];
    }
    if value < 128 {
        return alloc::vec![value as u8];
    }

    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(15);
    let significant = &bytes[start..];

    let mut result = Vec::with_capacity(1 + significant.len());
    result.push(0x80 + significant.len() as u8);
    result.extend_from_slice(significant);
    result
}

fn rlp_encode_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.is_empty() {
        return alloc::vec![0x80];
    }
    if bytes.len() == 1 && bytes[0] < 128 {
        return alloc::vec![bytes[0]];
    }

    if bytes.len() < 56 {
        let mut result = Vec::with_capacity(1 + bytes.len());
        result.push(0x80 + bytes.len() as u8);
        result.extend_from_slice(bytes);
        result
    } else {
        let len_bytes = encode_length(bytes.len());
        let mut result = Vec::with_capacity(1 + len_bytes.len() + bytes.len());
        result.push(0xb7 + len_bytes.len() as u8);
        result.extend_from_slice(&len_bytes);
        result.extend_from_slice(bytes);
        result
    }
}

fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_len: usize = items.iter().map(|i| i.len()).sum();

    if payload_len < 56 {
        let mut result = Vec::with_capacity(1 + payload_len);
        result.push(0xc0 + payload_len as u8);
        for item in items {
            result.extend_from_slice(item);
        }
        result
    } else {
        let len_bytes = encode_length(payload_len);
        let mut result = Vec::with_capacity(1 + len_bytes.len() + payload_len);
        result.push(0xf7 + len_bytes.len() as u8);
        result.extend_from_slice(&len_bytes);
        for item in items {
            result.extend_from_slice(item);
        }
        result
    }
}

fn encode_length(len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }

    let bytes = (len as u64).to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    bytes[start..].to_vec()
}

fn encode_access_list(access_list: &[AccessListItem]) -> Vec<u8> {
    let mut items = Vec::new();

    for item in access_list {
        let mut entry_items = Vec::new();
        entry_items.push(rlp_encode_bytes(&item.address));

        let storage_keys: Vec<Vec<u8>> = item
            .storage_keys
            .iter()
            .map(|k| rlp_encode_bytes(k))
            .collect();
        entry_items.push(rlp_encode_list(&storage_keys));

        items.push(rlp_encode_list(&entry_items));
    }

    rlp_encode_list(&items)
}

pub fn encode_eth_transfer(to: &[u8; 20], value_wei: u128) -> TransactionRequest {
    TransactionRequest::new_eip1559(1)
        .with_to(*to)
        .with_value(value_wei)
        .with_gas_limit(21000)
}

pub fn encode_erc20_transfer(
    token: &[u8; 20],
    to: &[u8; 20],
    amount: u128,
) -> TransactionRequest {
    let selector: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

    let mut data = selector.to_vec();

    let mut to_padded = [0u8; 32];
    to_padded[12..32].copy_from_slice(to);
    data.extend_from_slice(&to_padded);

    let amount_bytes = amount.to_be_bytes();
    let mut amount_padded = [0u8; 32];
    amount_padded[16..32].copy_from_slice(&amount_bytes);
    data.extend_from_slice(&amount_padded);

    TransactionRequest::new_eip1559(1)
        .with_to(*token)
        .with_data(data)
        .with_gas_limit(65000)
}

pub fn encode_erc20_approve(
    token: &[u8; 20],
    spender: &[u8; 20],
    amount: u128,
) -> TransactionRequest {
    let selector: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

    let mut data = selector.to_vec();

    let mut spender_padded = [0u8; 32];
    spender_padded[12..32].copy_from_slice(spender);
    data.extend_from_slice(&spender_padded);

    let amount_bytes = amount.to_be_bytes();
    let mut amount_padded = [0u8; 32];
    amount_padded[16..32].copy_from_slice(&amount_bytes);
    data.extend_from_slice(&amount_padded);

    TransactionRequest::new_eip1559(1)
        .with_to(*token)
        .with_data(data)
        .with_gas_limit(50000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rlp_encode_u64() {
        assert_eq!(rlp_encode_u64(0), vec![0x80]);
        assert_eq!(rlp_encode_u64(1), vec![0x01]);
        assert_eq!(rlp_encode_u64(127), vec![0x7f]);
        assert_eq!(rlp_encode_u64(128), vec![0x81, 0x80]);
        assert_eq!(rlp_encode_u64(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_rlp_encode_bytes() {
        assert_eq!(rlp_encode_bytes(&[]), vec![0x80]);
        assert_eq!(rlp_encode_bytes(&[0x00]), vec![0x00]);
        assert_eq!(rlp_encode_bytes(&[0x7f]), vec![0x7f]);
        assert_eq!(rlp_encode_bytes(&[0x80]), vec![0x81, 0x80]);
    }

    #[test]
    fn test_rlp_encode_list() {
        assert_eq!(rlp_encode_list(&[]), vec![0xc0]);
        assert_eq!(
            rlp_encode_list(&[vec![0x01], vec![0x02]]),
            vec![0xc2, 0x01, 0x02]
        );
    }
}
