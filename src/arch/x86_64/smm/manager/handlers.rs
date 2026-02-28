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

use crate::arch::x86_64::smm::constants::SMM_ENTRY_OFFSET;
use crate::arch::x86_64::smm::error::SmmError;
use crate::arch::x86_64::smm::hw::read_smram;
use crate::arch::x86_64::smm::types::SmmHandler;
use super::state::SmmManager;

impl SmmManager {
    pub(crate) fn enumerate_handlers(&self) -> Result<(), SmmError> {
        let regions = self.regions.read();
        let mut handlers = self.handlers.write();

        for region in regions.iter() {
            let handler_entry = region.base + SMM_ENTRY_OFFSET;
            let handler_code = read_smram(handler_entry, 4096);
            let hash = crate::crypto::hash::sha256(&handler_code);

            handlers.push(SmmHandler {
                entry_point: handler_entry,
                size: 4096,
                hash,
                verified: false,
                region_type: region.region_type,
            });
        }

        for handler in handlers.iter_mut() {
            handler.verified = self.verify_handler_code(handler);
            if handler.verified {
                self.stats.handlers_verified.fetch_add(1, Ordering::SeqCst);
            }
        }

        Ok(())
    }

    pub(crate) fn verify_handler_code(&self, handler: &SmmHandler) -> bool {
        if handler.entry_point == 0 || handler.size == 0 {
            return false;
        }

        let current_code = read_smram(handler.entry_point, handler.size as usize);
        let current_hash = crate::crypto::hash::sha256(&current_code);

        let mut matches = true;
        for i in 0..32 {
            if current_hash[i] != handler.hash[i] {
                matches = false;
            }
        }

        matches
    }
}
