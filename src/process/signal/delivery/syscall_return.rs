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

use super::dispatch::dispatch_one;
use crate::process::context::{read_saved_context, Context};
use crate::process::signal::constants::SIG_COUNT;
use crate::process::{
    clear_interrupt_context, current_pid, save_interrupt_context, with_process,
};

pub fn run_on_syscall_return(build_saved_ctx: impl FnOnce() -> Context) {
    let pid = match current_pid() {
        Some(p) => p,
        None => return,
    };
    let mut saved = false;
    for _ in 0..SIG_COUNT {
        let signo = with_process(pid, |pcb| pcb.signals.lock().next_pending_unblocked()).flatten();
        let s = match signo {
            Some(s) => s,
            None => break,
        };
        if !saved {
            save_interrupt_context(pid, build_saved_ctx());
            saved = true;
        }
        if dispatch_one(pid, s) {
            if let Some(ctx) = read_saved_context(pid) {
                ctx.resume_user();
            }
            break;
        }
    }
    if saved {
        clear_interrupt_context(pid);
    }
}
