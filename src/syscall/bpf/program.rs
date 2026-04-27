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

use super::types::BpfProgType;
use super::verifier::BpfVerifier;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};
use spin::Mutex;

static NEXT_PROG_FD: AtomicI32 = AtomicI32::new(300);
static PROGRAMS: Mutex<BTreeMap<i32, BpfProgram>> = Mutex::new(BTreeMap::new());
static ATTACHMENTS: Mutex<BTreeMap<(i32, i32, u32), i32>> = Mutex::new(BTreeMap::new());

pub struct BpfProgram {
    pub fd: i32,
    pub prog_type: BpfProgType,
    pub insns: Vec<u64>,
    pub name: [u8; 16],
    pub attached_count: u32,
}

impl BpfProgram {
    pub fn load(prog_type: BpfProgType, insns: Vec<u64>, name: [u8; 16]) -> Result<i32, i32> {
        if insns.is_empty() || insns.len() > 4096 {
            return Err(22);
        }
        BpfVerifier::verify(&insns)?;
        let fd = NEXT_PROG_FD.fetch_add(1, Ordering::SeqCst);
        let prog = BpfProgram { fd, prog_type, insns, name, attached_count: 0 };
        PROGRAMS.lock().insert(fd, prog);
        Ok(fd)
    }

    pub fn get(fd: i32) -> Option<BpfProgType> {
        PROGRAMS.lock().get(&fd).map(|p| p.prog_type)
    }

    pub fn close(fd: i32) -> Result<(), i32> {
        let mut progs = PROGRAMS.lock();
        if let Some(prog) = progs.get(&fd) {
            if prog.attached_count > 0 {
                return Err(16);
            }
        }
        progs.remove(&fd).map(|_| ()).ok_or(9)
    }

    pub fn attach(prog_fd: i32, target_fd: i32, attach_type: u32) -> Result<(), i32> {
        let mut progs = PROGRAMS.lock();
        let prog = progs.get_mut(&prog_fd).ok_or(9)?;
        let key = (prog_fd, target_fd, attach_type);
        let mut attachments = ATTACHMENTS.lock();
        if attachments.contains_key(&key) {
            return Err(17);
        }
        attachments.insert(key, prog_fd);
        prog.attached_count += 1;
        Ok(())
    }

    pub fn detach(prog_fd: i32, target_fd: i32, attach_type: u32) -> Result<(), i32> {
        let key = (prog_fd, target_fd, attach_type);
        let mut attachments = ATTACHMENTS.lock();
        if attachments.remove(&key).is_none() {
            return Err(2);
        }
        let mut progs = PROGRAMS.lock();
        if let Some(prog) = progs.get_mut(&prog_fd) {
            prog.attached_count = prog.attached_count.saturating_sub(1);
        }
        Ok(())
    }

    pub fn is_attached(prog_fd: i32, target_fd: i32, attach_type: u32) -> bool {
        ATTACHMENTS.lock().contains_key(&(prog_fd, target_fd, attach_type))
    }

    pub fn get_attachments(prog_fd: i32) -> Vec<(i32, u32)> {
        ATTACHMENTS
            .lock()
            .iter()
            .filter_map(
                |((pfd, tfd, at), _)| {
                    if *pfd == prog_fd {
                        Some((*tfd, *at))
                    } else {
                        None
                    }
                },
            )
            .collect()
    }
}
