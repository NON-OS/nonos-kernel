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

use core::sync::atomic::Ordering;

use crate::arch::x86_64::smm::constants::{LEGACY_SMRAM_BASE, LEGACY_SMRAM_SIZE};
use crate::arch::x86_64::smm::error::SmmError;
use crate::arch::x86_64::smm::hw::read_smram;
use super::state::SmmManager;

impl SmmManager {
    pub fn verify_integrity(&self) -> Result<bool, SmmError> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(SmmError::NotInitialized);
        }

        self.stats.integrity_checks.fetch_add(1, Ordering::SeqCst);

        let handlers = self.handlers.read();
        let regions = self.regions.read();

        for handler in handlers.iter() {
            let current_code = read_smram(handler.entry_point, handler.size as usize);
            let current_hash = crate::crypto::hash::sha256(&current_code);

            let mut matches = true;
            for i in 0..32 {
                if current_hash[i] != handler.hash[i] {
                    matches = false;
                }
            }

            if !matches {
                self.stats.integrity_failures.fetch_add(1, Ordering::SeqCst);
                crate::log::info!(
                    "SMM integrity FAILED: handler at 0x{:x}",
                    handler.entry_point
                );
                return Ok(false);
            }

            let in_valid_region = regions
                .iter()
                .any(|r| r.contains_range(handler.entry_point, handler.size as u64));

            if !in_valid_region {
                let in_legacy = handler.entry_point >= LEGACY_SMRAM_BASE
                    && handler.entry_point + handler.size as u64
                        <= LEGACY_SMRAM_BASE + LEGACY_SMRAM_SIZE;

                if !in_legacy {
                    self.stats.integrity_failures.fetch_add(1, Ordering::SeqCst);
                    crate::log::info!(
                        "SMM integrity FAILED: handler at 0x{:x} outside valid region",
                        handler.entry_point
                    );
                    return Ok(false);
                }
            }
        }

        for region in regions.iter() {
            if !region.protected {
                crate::log::info!(
                    "SMM integrity FAILED: region at 0x{:x} not protected",
                    region.base
                );
                return Ok(false);
            }
        }

        crate::log::info!("SMM integrity verified: {} handlers", handlers.len());
        Ok(true)
    }
}
