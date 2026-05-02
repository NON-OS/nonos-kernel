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

use crate::process::signal::constants::SIG_COUNT;
use crate::process::{current_pid, with_process};

pub fn get_pending_signal(pid: u32) -> u32 {
    with_process(pid, |pcb| pcb.signals.lock().next_pending_unblocked().unwrap_or(0) as u32)
        .unwrap_or(0)
}

pub fn clear_pending_signal(pid: u32, signo: u32) {
    if signo == 0 || signo as usize >= SIG_COUNT {
        return;
    }
    with_process(pid, |pcb| pcb.signals.lock().clear_pending(signo as u8));
}

pub fn has_pending_signals() -> bool {
    let pid = match current_pid() {
        Some(p) => p,
        None => return false,
    };
    with_process(pid, |pcb| pcb.signals.lock().has_pending_signals()).unwrap_or(false)
}
