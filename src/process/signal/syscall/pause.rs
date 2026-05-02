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

use crate::process::{current_pid, with_process};

const EINTR: i64 = -4;
const ESRCH: i64 = -3;

/// Block until a deliverable signal arrives, then return EINTR. The
/// wake condition is the same `pending & !blocked` check delivery
/// selection uses — a blocked pending signal does not unblock pause.
pub fn sys_pause() -> i64 {
    let pid = match current_pid() {
        Some(p) => p,
        None => return ESRCH,
    };
    loop {
        let deliverable = with_process(pid, |pcb| {
            pcb.signals.lock().next_pending_unblocked().is_some()
        })
        .unwrap_or(false);
        if deliverable {
            return EINTR;
        }
        crate::sched::yield_now();
    }
}
