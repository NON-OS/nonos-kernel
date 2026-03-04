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

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::zk_engine::ZKError;
use crate::zk_engine::groth16::{Proof, ProvingKey, VerifyingKey};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum WalletProofType {
    BalanceOwnership = 0,
    TransactionAuth = 1,
    StealthSpendKey = 2,
    BalanceSufficiency = 3,
}

pub(crate) struct WalletZKKeys {
    pub(crate) balance_ownership_pk: Option<ProvingKey>,
    pub(crate) balance_ownership_vk: Option<VerifyingKey>,
    pub(crate) tx_auth_pk: Option<ProvingKey>,
    pub(crate) tx_auth_vk: Option<VerifyingKey>,
    pub(crate) stealth_pk: Option<ProvingKey>,
    pub(crate) stealth_vk: Option<VerifyingKey>,
    pub(crate) sufficiency_pk: Option<ProvingKey>,
    pub(crate) sufficiency_vk: Option<VerifyingKey>,
}

impl WalletZKKeys {
    pub(crate) const fn new() -> Self {
        Self {
            balance_ownership_pk: None,
            balance_ownership_vk: None,
            tx_auth_pk: None,
            tx_auth_vk: None,
            stealth_pk: None,
            stealth_vk: None,
            sufficiency_pk: None,
            sufficiency_vk: None,
        }
    }
}

pub(crate) static ZK_KEYS: Mutex<WalletZKKeys> = Mutex::new(WalletZKKeys::new());
pub(crate) static ZK_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
pub(crate) struct WalletZKProof {
    pub(crate) proof_type: WalletProofType,
    pub(crate) proof: Proof,
    pub(crate) public_inputs: Vec<[u8; 32]>,
    pub(crate) commitment: [u8; 32],
}

impl WalletZKProof {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(256);

        result.push(self.proof_type as u8);

        let proof_bytes = self.proof.serialize();
        result.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
        result.extend_from_slice(&proof_bytes);

        result.push(self.public_inputs.len() as u8);
        for input in &self.public_inputs {
            result.extend_from_slice(input);
        }

        result.extend_from_slice(&self.commitment);

        result
    }

    pub(crate) fn from_bytes(data: &[u8]) -> Result<Self, ZKError> {
        if data.len() < 38 {
            return Err(ZKError::InvalidFormat);
        }

        let proof_type = match data[0] {
            0 => WalletProofType::BalanceOwnership,
            1 => WalletProofType::TransactionAuth,
            2 => WalletProofType::StealthSpendKey,
            3 => WalletProofType::BalanceSufficiency,
            _ => return Err(ZKError::InvalidFormat),
        };

        let proof_len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as usize;
        if data.len() < 5 + proof_len + 1 {
            return Err(ZKError::InvalidFormat);
        }

        let proof = Proof::deserialize(&data[5..5 + proof_len])?;

        let mut offset = 5 + proof_len;
        let num_inputs = data[offset] as usize;
        offset += 1;

        let mut public_inputs = Vec::with_capacity(num_inputs);
        for _ in 0..num_inputs {
            if offset + 32 > data.len() {
                return Err(ZKError::InvalidFormat);
            }
            let mut input = [0u8; 32];
            input.copy_from_slice(&data[offset..offset + 32]);
            public_inputs.push(input);
            offset += 32;
        }

        if offset + 32 > data.len() {
            return Err(ZKError::InvalidFormat);
        }
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&data[offset..offset + 32]);

        Ok(Self {
            proof_type,
            proof,
            public_inputs,
            commitment,
        })
    }
}

pub(crate) fn is_zk_available() -> bool {
    ZK_INITIALIZED.load(Ordering::SeqCst)
}

pub(crate) fn get_zk_status() -> (bool, u8, u8) {
    let initialized = ZK_INITIALIZED.load(Ordering::SeqCst);
    let keys = ZK_KEYS.lock();
    let circuits_ready = [
        keys.balance_ownership_pk.is_some(),
        keys.tx_auth_pk.is_some(),
        keys.stealth_pk.is_some(),
        keys.sufficiency_pk.is_some(),
    ].iter().filter(|&&x| x).count() as u8;
    drop(keys);
    (initialized, circuits_ready, 4)
}
