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

use alloc::{string::String, vec::Vec, collections::BTreeMap};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::RwLock;

use crate::crypto::ethereum::{EthAddress, Wallet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsuleCategory {
    System,
    Privacy,
    Security,
    Network,
    Utility,
    Development,
    Media,
    Finance,
    Communication,
}

#[derive(Debug, Clone)]
pub struct CapsuleMetadata {
    pub id: [u8; 32],
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub category: CapsuleCategory,
    pub size_bytes: u64,
    pub nox_fee: u128,
    pub signature: [u8; 64],
    pub ed25519_pubkey: [u8; 32],
    pub dilithium_signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallState {
    Pending,
    PaymentRequired,
    PaymentSubmitted,
    PaymentConfirmed,
    Downloading,
    Verifying,
    Installing,
    Installed,
    Failed,
}

#[derive(Debug, Clone)]
pub struct InstallationTask {
    pub capsule_id: [u8; 32],
    pub state: InstallState,
    pub tx_hash: Option<[u8; 32]>,
    pub progress_percent: u8,
    pub error: Option<String>,
}

#[derive(Debug)]
pub struct InstalledCapsule {
    pub metadata: CapsuleMetadata,
    pub install_timestamp: u64,
    pub code_hash: [u8; 32],
    pub active: AtomicBool,
}

impl Clone for InstalledCapsule {
    fn clone(&self) -> Self {
        Self {
            metadata: self.metadata.clone(),
            install_timestamp: self.install_timestamp,
            code_hash: self.code_hash,
            active: AtomicBool::new(self.active.load(Ordering::Relaxed)),
        }
    }
}

pub struct CapsuleStore {
    pub(super) available: RwLock<BTreeMap<[u8; 32], CapsuleMetadata>>,
    pub(super) installed: RwLock<BTreeMap<[u8; 32], InstalledCapsule>>,
    pub(super) pending_installs: RwLock<BTreeMap<[u8; 32], InstallationTask>>,
    pub(super) wallet: RwLock<Option<Wallet>>,
    pub(super) nonce: AtomicU64,
    pub(super) fee_receiver: EthAddress,
}
