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
use alloc::vec;
use alloc::vec::Vec;

use crate::crypto::secp256k1::{self, SecretKey};
use crate::crypto::sha3::keccak256;

use super::super::address::EthAddress;
use super::super::rlp::{rlp_encode_bytes, rlp_encode_list, rlp_encode_u128, rlp_encode_u64};
use super::super::NOX_TOKEN_ADDRESS;
use super::types::{Transaction, SignedTransaction};

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

        let v = self.chain_id * 2 + 35 + sig.recovery_id as u64;

        Some(SignedTransaction {
            tx: self.clone(),
            v,
            r: sig.r,
            s: sig.s,
        })
    }
}
