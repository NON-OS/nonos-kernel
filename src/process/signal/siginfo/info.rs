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

use super::code::SigCode;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SigInfo {
    pub signo: u8,
    pub code: SigCode,
    pub errno: i32,
    pub pid: u32,
    pub uid: u32,
    pub status: i32,
    pub addr: u64,
    pub value: i64,
    pub band: i64,
}

impl SigInfo {
    pub fn new_user(signo: u8, sender_pid: u32, sender_uid: u32) -> Self {
        Self { signo, code: SigCode::USER, pid: sender_pid, uid: sender_uid, ..Self::default() }
    }

    pub fn new_kernel(signo: u8) -> Self {
        Self { signo, code: SigCode::KERNEL, ..Self::default() }
    }

    pub fn new_fault(signo: u8, code: SigCode, addr: u64) -> Self {
        Self { signo, code, addr, ..Self::default() }
    }

    pub fn new_child(signo: u8, child_pid: u32, child_uid: u32, code: SigCode, status: i32) -> Self {
        Self { signo, code, pid: child_pid, uid: child_uid, status, ..Self::default() }
    }

    pub fn new_timer(signo: u8, timer_id: i32, overrun: i32) -> Self {
        Self {
            signo,
            code: SigCode::TIMER,
            pid: timer_id as u32,
            status: overrun,
            ..Self::default()
        }
    }

    pub fn new_poll(signo: u8, band: i64, fd: i32) -> Self {
        Self { signo, code: SigCode::POLL_IN, pid: fd as u32, band, ..Self::default() }
    }

    pub fn with_value(mut self, value: i64) -> Self {
        self.value = value;
        self
    }

    pub fn is_from_user(&self) -> bool {
        matches!(self.code, SigCode::USER | SigCode::QUEUE | SigCode::TKILL)
    }

    pub fn is_from_kernel(&self) -> bool {
        self.code == SigCode::KERNEL
    }
}
