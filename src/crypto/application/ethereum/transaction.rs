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

use alloc::vec;
use alloc::vec::Vec;
use crate::crypto::secp256k1::{self, PublicKey, RecoverableSignature, SecretKey};
use crate::crypto::sha3::keccak256;
use super::address::EthAddress;
use super::rlp::{rlp_encode_bytes, rlp_encode_list, rlp_encode_u128, rlp_encode_u64, trim_leading_zeros};
use super::{HEX_CHARS, NOX_TOKEN_ADDRESS};

#[derive(Clone, Debug)]
pub struct Transaction {
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: Option<EthAddress>,
    pub value: u128,
    pub data: Vec<u8>,
    pub chain_id: u64,
}

#[derive(Clone, Debug)]
pub struct SignedTransaction {
    pub tx: Transaction,
    pub v: u64,
    pub r: [u8; 32],
    pub s: [u8; 32],
}

impl Transaction {
    pub fn new_transfer(
        to: EthAddress,
        value: u128,
        nonce: u64,
        gas_price: u128,
        chain_id: u64,
    ) -> Self {
        Self {
            nonce,
            gas_price,
            gas_limit: 21000,
            to: Some(to),
            value,
            data: Vec::new(),
            chain_id,
        }
    }

    pub fn new_erc20_transfer(
        token: EthAddress,
        to: EthAddress,
        amount: u128,
        nonce: u64,
        gas_price: u128,
        chain_id: u64,
    ) -> Self {
        let mut data = Vec::with_capacity(68);
        data.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(&to.0);
        let mut amount_bytes = [0u8; 32];
        let amount_be = amount.to_be_bytes();
        amount_bytes[16..32].copy_from_slice(&amount_be);
        data.extend_from_slice(&amount_bytes);

        Self {
            nonce,
            gas_price,
            gas_limit: 65000,
            to: Some(token),
            value: 0,
            data,
            chain_id,
        }
    }

    pub fn new_nox_transfer(
        to: EthAddress,
        amount: u128,
        nonce: u64,
        gas_price: u128,
        chain_id: u64,
    ) -> Self {
        Self::new_erc20_transfer(
            EthAddress(NOX_TOKEN_ADDRESS),
            to,
            amount,
            nonce,
            gas_price,
            chain_id,
        )
    }

    pub fn signing_hash(&self) -> [u8; 32] {
        let rlp = self.rlp_encode_for_signing();
        keccak256(&rlp)
    }

    fn rlp_encode_for_signing(&self) -> Vec<u8> {
        let mut items = Vec::new();
        items.push(rlp_encode_u64(self.nonce));
        items.push(rlp_encode_u128(self.gas_price));
        items.push(rlp_encode_u64(self.gas_limit));
        items.push(match &self.to {
            Some(addr) => rlp_encode_bytes(&addr.0),
            None => vec![0x80],
        });
        items.push(rlp_encode_u128(self.value));
        items.push(rlp_encode_bytes(&self.data));
        items.push(rlp_encode_u64(self.chain_id));
        items.push(vec![0x80]);
        items.push(vec![0x80]);
        rlp_encode_list(&items)
    }

    pub fn sign(&self, sk: &SecretKey) -> Option<SignedTransaction> {
        let hash = self.signing_hash();
        let sig = secp256k1::sign(sk, &hash)?;

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig[0..32]);
        s.copy_from_slice(&sig[32..64]);
        let recovery_id = sig[64];

        let v = self.chain_id * 2 + 35 + recovery_id as u64;

        Some(SignedTransaction {
            tx: self.clone(),
            v,
            r,
            s,
        })
    }
}

impl SignedTransaction {
    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut items = Vec::new();
        items.push(rlp_encode_u64(self.tx.nonce));
        items.push(rlp_encode_u128(self.tx.gas_price));
        items.push(rlp_encode_u64(self.tx.gas_limit));
        items.push(match &self.tx.to {
            Some(addr) => rlp_encode_bytes(&addr.0),
            None => vec![0x80],
        });
        items.push(rlp_encode_u128(self.tx.value));
        items.push(rlp_encode_bytes(&self.tx.data));
        items.push(rlp_encode_u64(self.v));
        items.push(rlp_encode_bytes(trim_leading_zeros(&self.r)));
        items.push(rlp_encode_bytes(trim_leading_zeros(&self.s)));
        rlp_encode_list(&items)
    }

    pub fn to_hex(&self) -> Vec<u8> {
        let raw = self.rlp_encode();
        let mut hex = Vec::with_capacity(2 + raw.len() * 2);
        hex.push(b'0');
        hex.push(b'x');
        for byte in raw {
            hex.push(HEX_CHARS[(byte >> 4) as usize]);
            hex.push(HEX_CHARS[(byte & 0x0f) as usize]);
        }
        hex
    }
}

pub struct Wallet {
    secret_key: SecretKey,
    public_key: PublicKey,
    address: EthAddress,
}

impl Wallet {
    pub fn generate() -> Self {
        let (sk, pk) = secp256k1::generate_keypair();
        let address = EthAddress::from_public_key(&pk);
        Self {
            secret_key: sk,
            public_key: pk,
            address,
        }
    }

    pub fn from_secret_key(sk: SecretKey) -> Option<Self> {
        let pk = secp256k1::public_key_from_secret(&sk)?;
        let address = EthAddress::from_public_key(&pk);
        Some(Self {
            secret_key: sk,
            public_key: pk,
            address,
        })
    }

    pub fn address(&self) -> &EthAddress {
        &self.address
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn sign_transaction(&self, tx: &Transaction) -> Option<SignedTransaction> {
        tx.sign(&self.secret_key)
    }

    pub fn sign_message(&self, message: &[u8]) -> Option<RecoverableSignature> {
        let prefixed = eth_sign_message(message);
        secp256k1::sign(&self.secret_key, &prefixed)
    }
}

impl Drop for Wallet {
    fn drop(&mut self) {
        // SAFETY: Zeroing secret key material to prevent leakage after drop.
        // The pointer is valid because it points to an owned field.
        for byte in &mut self.secret_key {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
    }
}

pub fn eth_sign_message(message: &[u8]) -> [u8; 32] {
    let prefix = b"\x19Ethereum Signed Message:\n";
    let len_str = format_usize(message.len());
    let mut data = Vec::with_capacity(prefix.len() + len_str.len() + message.len());
    data.extend_from_slice(prefix);
    data.extend_from_slice(&len_str);
    data.extend_from_slice(message);

    keccak256(&data)
}

fn format_usize(n: usize) -> Vec<u8> {
    if n == 0 {
        return vec![b'0'];
    }

    let mut digits = Vec::new();
    let mut num = n;
    while num > 0 {
        digits.push(b'0' + (num % 10) as u8);
        num /= 10;
    }
    digits.reverse();
    digits
}

pub fn parse_wei(eth_str: &str) -> Option<u128> {
    let bytes = eth_str.as_bytes();
    let mut value: u128 = 0;
    let mut decimals: Option<u8> = None;
    let mut decimal_count: u8 = 0;

    for &c in bytes {
        match c {
            b'0'..=b'9' => {
                let digit = (c - b'0') as u128;
                value = value.checked_mul(10)?.checked_add(digit)?;
                if decimals.is_some() {
                    decimal_count += 1;
                    if decimal_count > 18 {
                        return None;
                    }
                }
            }
            b'.' => {
                if decimals.is_some() {
                    return None;
                }
                decimals = Some(0);
            }
            _ => return None,
        }
    }

    let remaining_decimals = 18 - decimal_count;
    for _ in 0..remaining_decimals {
        value = value.checked_mul(10)?;
    }

    Some(value)
}

pub fn wei_to_gwei(wei: u128) -> u128 {
    wei / 1_000_000_000
}

pub fn gwei_to_wei(gwei: u128) -> u128 {
    gwei * 1_000_000_000
}
