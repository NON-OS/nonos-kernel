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

use crate::syscall::signals::types::PendingSignal;

pub const SFD_CLOEXEC: i32 = 0x80000;
pub const SFD_NONBLOCK: i32 = 0x800;

pub const EINVAL: i32 = 22;
pub const EAGAIN: i32 = 11;
pub const ENOMEM: i32 = 12;
pub const EBADF: i32 = 9;

pub const SIGNALFD_SIGINFO_SIZE: usize = 128;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SignalfdSiginfo {
    pub ssi_signo: u32,
    pub ssi_errno: i32,
    pub ssi_code: i32,
    pub ssi_pid: u32,
    pub ssi_uid: u32,
    pub ssi_fd: i32,
    pub ssi_tid: u32,
    pub ssi_band: u32,
    pub ssi_overrun: u32,
    pub ssi_trapno: u32,
    pub ssi_status: i32,
    pub ssi_int: i32,
    pub ssi_ptr: u64,
    pub ssi_utime: u64,
    pub ssi_stime: u64,
    pub ssi_addr: u64,
    pub ssi_addr_lsb: u16,
    _pad: [u8; 46],
}

impl Default for SignalfdSiginfo {
    fn default() -> Self {
        Self {
            ssi_signo: 0,
            ssi_errno: 0,
            ssi_code: 0,
            ssi_pid: 0,
            ssi_uid: 0,
            ssi_fd: 0,
            ssi_tid: 0,
            ssi_band: 0,
            ssi_overrun: 0,
            ssi_trapno: 0,
            ssi_status: 0,
            ssi_int: 0,
            ssi_ptr: 0,
            ssi_utime: 0,
            ssi_stime: 0,
            ssi_addr: 0,
            ssi_addr_lsb: 0,
            _pad: [0u8; 46],
        }
    }
}

impl SignalfdSiginfo {
    pub fn from_pending(sig: &PendingSignal) -> Self {
        let mut info = Self::default();
        info.ssi_signo = sig.signo;
        info.ssi_code = sig.code;
        info.ssi_pid = sig.pid;
        info.ssi_uid = sig.uid;
        info.ssi_ptr = sig.value;
        info
    }

    /// # Safety
    /// Serializes struct to bytes field-by-field. Avoids transmute which
    /// could leak uninitialized padding bytes to userspace.
    pub fn to_bytes(&self) -> [u8; SIGNALFD_SIGINFO_SIZE] {
        let mut buf = [0u8; SIGNALFD_SIGINFO_SIZE];
        let mut offset = 0;

        buf[offset..offset + 4].copy_from_slice(&self.ssi_signo.to_ne_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&self.ssi_errno.to_ne_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&self.ssi_code.to_ne_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&self.ssi_pid.to_ne_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&self.ssi_uid.to_ne_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&self.ssi_fd.to_ne_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&self.ssi_tid.to_ne_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&self.ssi_band.to_ne_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&self.ssi_overrun.to_ne_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&self.ssi_trapno.to_ne_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&self.ssi_status.to_ne_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&self.ssi_int.to_ne_bytes());
        offset += 4;
        buf[offset..offset + 8].copy_from_slice(&self.ssi_ptr.to_ne_bytes());
        offset += 8;
        buf[offset..offset + 8].copy_from_slice(&self.ssi_utime.to_ne_bytes());
        offset += 8;
        buf[offset..offset + 8].copy_from_slice(&self.ssi_stime.to_ne_bytes());
        offset += 8;
        buf[offset..offset + 8].copy_from_slice(&self.ssi_addr.to_ne_bytes());
        offset += 8;
        buf[offset..offset + 2].copy_from_slice(&self.ssi_addr_lsb.to_ne_bytes());

        buf
    }
}

pub struct SignalfdInfo {
    pub pending_count: usize,
    pub mask: u64,
}

pub struct SignalfdStats {
    pub active_count: usize,
    pub total_pending_signals: usize,
    pub average_mask_size: usize,
}
