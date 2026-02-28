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
use core::sync::atomic::Ordering;

use crate::arch::x86_64::syscall::security::SecurityConfig;
use crate::arch::x86_64::syscall::stats::{SyscallStats, SyscallRecord};
use super::core::SyscallManager;

impl SyscallManager {
    pub fn detect_hooks(&self) -> bool {
        let table = self.table.read();
        let mut data = Vec::new();

        for (num, info) in table.iter() {
            data.extend_from_slice(&num.to_le_bytes());
            data.extend_from_slice(&(info.handler as *const () as u64).to_le_bytes());
        }

        let current_hash = crate::crypto::hash::sha3_256(&data);
        let original = self.original_hash.read();

        self.stats.integrity_checks.fetch_add(1, Ordering::Relaxed);
        self.stats.last_integrity_check_ns.store(crate::time::now_ns(), Ordering::Relaxed);

        if current_hash != *original {
            self.stats.hook_detections.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        false
    }

    pub fn verify_integrity(&self) -> bool {
        !self.detect_hooks()
    }

    pub fn get_statistics(&self) -> SyscallStats {
        self.stats.snapshot()
    }

    pub fn get_audit_log(&self) -> Vec<SyscallRecord> {
        self.audit_log.lock().clone()
    }

    pub fn configure(&self, config: SecurityConfig) {
        *self.config.write() = config;
    }
}
