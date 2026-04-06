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
use alloc::vec::Vec;
use spin::Mutex;
use core::sync::atomic::{AtomicI32, Ordering};
use super::types::BpfProgType;
use super::verifier::BpfVerifier;

static NEXT_PROG_FD: AtomicI32 = AtomicI32::new(300);
static PROGRAMS: Mutex<BTreeMap<i32, BpfProgram>> = Mutex::new(BTreeMap::new());

pub struct BpfProgram {
    pub fd: i32,
    pub prog_type: BpfProgType,
    pub insns: Vec<u64>,
    pub name: [u8; 16],
}

impl BpfProgram {
    pub fn load(prog_type: BpfProgType, insns: Vec<u64>, name: [u8; 16]) -> Result<i32, i32> {
        if insns.is_empty() || insns.len() > 4096 {
            return Err(22);
        }
        BpfVerifier::verify(&insns)?;
        let fd = NEXT_PROG_FD.fetch_add(1, Ordering::SeqCst);
        let prog = BpfProgram { fd, prog_type, insns, name };
        PROGRAMS.lock().insert(fd, prog);
        Ok(fd)
    }

    pub fn get(fd: i32) -> Option<BpfProgType> {
        PROGRAMS.lock().get(&fd).map(|p| p.prog_type)
    }

    pub fn close(fd: i32) -> Result<(), i32> {
        PROGRAMS.lock().remove(&fd).map(|_| ()).ok_or(9)
    }

    pub fn attach(_prog_fd: i32, _target_fd: i32, _attach_type: u32) -> Result<(), i32> {
        Ok(())
    }

    pub fn detach(_prog_fd: i32, _target_fd: i32, _attach_type: u32) -> Result<(), i32> {
        Ok(())
    }
}
