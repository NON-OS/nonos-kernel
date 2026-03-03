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

use alloc::{vec::Vec, collections::BTreeMap};
use core::sync::atomic::{AtomicU64, AtomicU32, AtomicBool, Ordering};
use spin::{RwLock, Mutex};

use crate::arch::x86_64::syscall::error::SyscallError;
use crate::arch::x86_64::syscall::msr;
use crate::arch::x86_64::syscall::security::SecurityConfig;
use crate::arch::x86_64::syscall::stats::{SyscallRecord, InternalStats};
use super::types::SyscallInfo;
use super::entry::syscall_entry_asm;
use super::state::INITIALIZED;

pub struct SyscallManager {
    pub(crate) table: RwLock<BTreeMap<u64, SyscallInfo>>,
    pub(crate) original_hash: RwLock<[u8; 32]>,
    pub(crate) audit_log: Mutex<Vec<SyscallRecord>>,
    pub(crate) stats: InternalStats,
    pub(crate) config: RwLock<SecurityConfig>,
    pub(crate) fork_counter: AtomicU32,
    pub(crate) fork_reset_time: AtomicU64,
    pub(crate) rate_limited: AtomicBool,
}

impl SyscallManager {
    pub const fn new() -> Self {
        Self {
            table: RwLock::new(BTreeMap::new()),
            original_hash: RwLock::new([0u8; 32]),
            audit_log: Mutex::new(Vec::new()),
            stats: InternalStats::new(),
            config: RwLock::new(SecurityConfig {
                max_fork_rate: 100,
                validate_paths: true,
                verify_executables: true,
                max_syscall_rate: 0,
                audit_enabled: true,
                max_audit_records: 1000,
            }),
            fork_counter: AtomicU32::new(0),
            fork_reset_time: AtomicU64::new(0),
            rate_limited: AtomicBool::new(false),
        }
    }

    pub fn is_rate_limited(&self) -> bool {
        self.rate_limited.load(Ordering::Relaxed)
    }

    pub fn set_rate_limited(&self, limited: bool) {
        self.rate_limited.store(limited, Ordering::Relaxed);
    }

    pub fn init(&self) -> Result<(), SyscallError> {
        if INITIALIZED.load(Ordering::SeqCst) {
            return Err(SyscallError::AlreadyInitialized);
        }

        self.setup_fast_syscalls()?;
        self.initialize_table();
        self.compute_table_hash();

        INITIALIZED.store(true, Ordering::SeqCst);
        crate::log_info!("Syscall subsystem initialized");

        Ok(())
    }

    fn setup_fast_syscalls(&self) -> Result<(), SyscallError> {
        msr::setup_star(0x08, 0x10, 0x1B, 0x23);
        let entry_point = syscall_entry_asm as *const () as u64;
        msr::setup_lstar(entry_point);
        msr::setup_fmask();
        msr::enable_sce();
        Ok(())
    }
}
