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

use alloc::collections::BTreeMap;
use spin::Mutex;

#[derive(Debug, Clone, Copy)]
pub struct RseqRegistration {
    pub rseq_ptr: u64,
    pub rseq_len: u32,
    pub signature: u32,
}

static RSEQ_REGISTRATIONS: Mutex<BTreeMap<u64, RseqRegistration>> = Mutex::new(BTreeMap::new());

pub struct RseqState;

impl RseqState {
    pub fn register(pid: u64, rseq_ptr: u64, rseq_len: u32, sig: u32) -> Result<(), i32> {
        let mut regs = RSEQ_REGISTRATIONS.lock();
        if regs.contains_key(&pid) {
            return Err(16);
        }
        regs.insert(pid, RseqRegistration { rseq_ptr, rseq_len, signature: sig });
        Ok(())
    }

    pub fn unregister(pid: u64, rseq_ptr: u64, rseq_len: u32, sig: u32) -> Result<(), i32> {
        let mut regs = RSEQ_REGISTRATIONS.lock();
        if let Some(reg) = regs.get(&pid) {
            if reg.rseq_ptr != rseq_ptr || reg.rseq_len != rseq_len || reg.signature != sig {
                return Err(22);
            }
            regs.remove(&pid);
            Ok(())
        } else {
            Err(22)
        }
    }

    pub fn get(pid: u64) -> Option<RseqRegistration> {
        RSEQ_REGISTRATIONS.lock().get(&pid).copied()
    }

    pub fn is_registered(pid: u64) -> bool {
        RSEQ_REGISTRATIONS.lock().contains_key(&pid)
    }

    pub fn update_cpu(pid: u64) {
        if let Some(reg) = Self::get(pid) {
            let cpu_id = crate::smp::current_cpu_id() as u32;
            let _ = crate::usercopy::write_user_value(reg.rseq_ptr + 4, &cpu_id);
        }
    }
}
