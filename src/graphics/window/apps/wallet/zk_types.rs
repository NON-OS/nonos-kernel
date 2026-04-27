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
use crate::zk_engine::groth16::{Proof, ProvingKey, VerifyingKey};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum WalletProofType {
    BalanceOwnership = 0,
    StealthSpendKey = 2,
}

pub(crate) struct WalletZKKeys {
    pub balance_ownership_pk: Option<ProvingKey>,
    pub balance_ownership_vk: Option<VerifyingKey>,
    pub stealth_pk: Option<ProvingKey>,
    pub stealth_vk: Option<VerifyingKey>,
}
impl WalletZKKeys {
    pub(crate) const fn new() -> Self {
        Self {
            balance_ownership_pk: None,
            balance_ownership_vk: None,
            stealth_pk: None,
            stealth_vk: None,
        }
    }
}

pub(crate) static ZK_KEYS: Mutex<WalletZKKeys> = Mutex::new(WalletZKKeys::new());
pub(crate) static ZK_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
pub(crate) struct WalletZKProof {
    pub proof_type: WalletProofType,
    pub proof: Proof,
    pub public_inputs: Vec<[u8; 32]>,
    pub commitment: [u8; 32],
}
impl WalletZKProof {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut r = Vec::with_capacity(256);
        r.push(self.proof_type as u8);
        let pb = self.proof.serialize();
        r.extend_from_slice(&(pb.len() as u32).to_le_bytes());
        r.extend_from_slice(&pb);
        r.push(self.public_inputs.len() as u8);
        for i in &self.public_inputs {
            r.extend_from_slice(i);
        }
        r.extend_from_slice(&self.commitment);
        r
    }
}

pub(crate) fn is_zk_available() -> bool {
    ZK_INITIALIZED.load(Ordering::SeqCst)
}

pub(crate) fn get_zk_status() -> (bool, u8, u8) {
    let init = ZK_INITIALIZED.load(Ordering::SeqCst);
    let k = ZK_KEYS.lock();
    let ready =
        [k.balance_ownership_pk.is_some(), k.stealth_pk.is_some()].iter().filter(|&&x| x).count()
            as u8;
    drop(k);
    (init, ready, 2)
}
