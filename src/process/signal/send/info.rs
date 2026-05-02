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

use crate::process::signal::error::SignalError;
use crate::process::signal::helpers::{can_be_ignored, is_valid_signal};
use crate::process::signal::siginfo::SigInfo;
use crate::process::with_process_mut;

pub fn send_signal_info(target_pid: u32, signo: u8, info: SigInfo) -> Result<(), SignalError> {
    if !is_valid_signal(signo) {
        return Err(SignalError::InvalidSignal);
    }
    with_process_mut(target_pid, |pcb| {
        let mut signals = pcb.signals.lock();
        if signals.get_action(signo).is_ignored() && can_be_ignored(signo) {
            return Ok(());
        }
        signals.queue_signal(signo, info)
    })
    .ok_or(SignalError::ProcessNotFound)?
}
