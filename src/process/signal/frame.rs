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

use crate::process::context::Context;
use crate::process::signal::error::SignalError;
use crate::process::signal::siginfo::SigInfo;
use crate::usercopy::{read_user_value, write_user_value};

/// Sentinel written into every sigframe so `sigreturn` can refuse to
/// resume a frame that wasn't built by the kernel.
pub const SIGFRAME_MAGIC: u64 = 0x4E4F4E4F535F5346;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SigFrame {
    pub magic: u64,
    pub signo: u64,
    pub saved_blocked: u64,
    pub info: SigInfo,
    pub saved_ctx: Context,
}

impl SigFrame {
    pub fn new(signo: u8, info: SigInfo, saved_blocked: u64, saved_ctx: Context) -> Self {
        Self { magic: SIGFRAME_MAGIC, signo: signo as u64, saved_blocked, info, saved_ctx }
    }
}

/// Push a sigframe onto the user stack and return the new RSP.
pub fn push_to_user_stack(rsp: u64, frame: &SigFrame) -> Result<u64, SignalError> {
    let size = core::mem::size_of::<SigFrame>() as u64;
    let new_rsp = (rsp.checked_sub(size).ok_or(SignalError::BadAddress)?) & !0xF;
    // SAFETY: ek@nonos.systems — write_user_value performs a fault-checked
    // copy into the user address space at new_rsp. The pointer is the
    // user RSP minus the sigframe size aligned down to 16; if that page
    // is not mapped writable, write_user_value returns BadAddress and we
    // surface it. We never dereference the address in kernel mode.
    write_user_value(new_rsp, frame).map_err(|_| SignalError::BadAddress)?;
    Ok(new_rsp)
}

/// Read a sigframe from the user stack and validate its magic.
pub fn parse_from_user_stack(rsp: u64) -> Result<SigFrame, SignalError> {
    // SAFETY: ek@nonos.systems — read_user_value performs a fault-checked
    // copy from user space. We then validate the magic before trusting
    // any other field, so a forged frame at an arbitrary user RSP is
    // rejected before we hand its register values back to the restore
    // path.
    let frame: SigFrame = read_user_value(rsp).map_err(|_| SignalError::BadAddress)?;
    if frame.magic != SIGFRAME_MAGIC {
        return Err(SignalError::InvalidHandler);
    }
    Ok(frame)
}
