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

use super::default::perform_default;
use super::install::install_handler_frame;
use crate::process::signal::siginfo::SigInfo;
use crate::process::with_process_mut;

pub fn dispatch_one(pid: u32, signo: u8) -> bool {
    let result = with_process_mut(pid, |pcb| {
        let mut sigs = pcb.signals.lock();
        let info = sigs.dequeue_signal(signo).unwrap_or_else(|| {
            sigs.clear_pending(signo);
            SigInfo::new_kernel(signo)
        });
        let action = sigs.get_action(signo).clone();
        (info, action)
    });
    let (info, action) = match result {
        Some(v) => v,
        None => return false,
    };

    if action.is_handler() {
        if install_handler_frame(pid, signo, info, &action).is_ok() {
            return true;
        }
        perform_default(pid, signo);
        return false;
    }
    if action.is_default() {
        perform_default(pid, signo);
    }
    false
}
