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

use crate::process::context::{modify_saved_context, read_saved_context};
use crate::process::signal::error::SignalError;
use crate::process::signal::frame::{push_to_user_stack, SigFrame};
use crate::process::signal::sigaction::Sigaction;
use crate::process::signal::siginfo::SigInfo;
use crate::process::{with_process, with_process_mut};
use crate::usercopy::write_user_value;

pub fn install_handler_frame(
    pid: u32,
    signo: u8,
    info: SigInfo,
    action: &Sigaction,
) -> Result<(), SignalError> {
    let trampoline = pick_trampoline(pid, action)?;
    let saved_ctx = read_saved_context(pid).ok_or(SignalError::ProcessNotFound)?;
    let saved_blocked = with_process(pid, |pcb| pcb.signals.lock().get_blocked_mask())
        .ok_or(SignalError::ProcessNotFound)?;

    let frame = SigFrame::new(signo, info, saved_blocked, saved_ctx);
    let frame_rsp = push_to_user_stack(saved_ctx.rsp, &frame)?;
    let handler_rsp = frame_rsp - 8;
    write_user_value(handler_rsp, &trampoline).map_err(|_| SignalError::BadAddress)?;

    let new_blocked = saved_blocked | action.mask.as_bits() | (1u64 << signo as u64);
    with_process_mut(pid, |pcb| {
        pcb.signals.lock().set_blocked_mask(new_blocked);
    });

    let handler = action.handler as u64;
    modify_saved_context(pid, |ctx| {
        ctx.rip = handler;
        ctx.rsp = handler_rsp;
        ctx.rdi = signo as u64;
    });
    Ok(())
}

fn pick_trampoline(pid: u32, action: &Sigaction) -> Result<u64, SignalError> {
    if action.restorer != 0 {
        return Ok(action.restorer as u64);
    }
    let addr = with_process(pid, |pcb| pcb.signals.lock().trampoline_addr())
        .ok_or(SignalError::ProcessNotFound)?;
    if addr == 0 {
        Err(SignalError::InvalidHandler)
    } else {
        Ok(addr)
    }
}
