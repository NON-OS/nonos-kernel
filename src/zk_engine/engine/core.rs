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

use super::super::circuit::Circuit;
use super::super::groth16::{Groth16Prover, Groth16Verifier, ProvingKey, VerifyingKey};
use super::super::setup::TrustedSetup;
use super::super::types::{ZKConfig, ZKError, ZKStats};
use super::super::verification::VerificationCache;
use alloc::{boxed::Box, collections::BTreeMap};
use core::sync::atomic::{AtomicU32, AtomicU64};
use spin::RwLock;

pub struct ZKEngine {
    pub(crate) config: ZKConfig,
    pub(super) circuits: RwLock<BTreeMap<u32, Box<Circuit>>>,
    pub(super) proving_keys: RwLock<BTreeMap<u32, ProvingKey>>,
    pub(super) verifying_keys: RwLock<BTreeMap<u32, VerifyingKey>>,
    pub(crate) verification_cache: VerificationCache,
    pub(crate) stats: ZKStats,
    pub(super) next_circuit_id: AtomicU32,
}

impl ZKEngine {
    pub fn new(config: ZKConfig) -> Result<Self, ZKError> {
        let setup = TrustedSetup::load_or_generate(&config)?;
        let _ = Groth16Prover::new(&setup)?;
        let _ = Groth16Verifier::new(&setup)?;
        Ok(ZKEngine {
            config: config.clone(),
            circuits: RwLock::new(BTreeMap::new()),
            proving_keys: RwLock::new(BTreeMap::new()),
            verifying_keys: RwLock::new(BTreeMap::new()),
            verification_cache: VerificationCache::new(),
            stats: ZKStats {
                proofs_generated: AtomicU64::new(0),
                proofs_verified: AtomicU64::new(0),
                verification_failures: AtomicU64::new(0),
                circuits_compiled: AtomicU32::new(0),
                total_proving_time_ms: AtomicU64::new(0),
                total_verification_time_ms: AtomicU64::new(0),
            },
            next_circuit_id: AtomicU32::new(1),
        })
    }

    pub fn get_stats(&self) -> &ZKStats {
        &self.stats
    }

    pub fn cleanup(&self) {
        self.verification_cache.clear();
        crate::log::info!("ZK engine cleanup completed");
    }
}
