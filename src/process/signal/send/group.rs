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

use core::sync::atomic::Ordering;

use super::signal::send_signal;
use crate::process::get_process_table;
use crate::process::signal::error::SignalError;

pub fn send_signal_to_group(pgrp: i32, signo: u32) -> Result<(), SignalError> {
    if pgrp <= 0 {
        return Err(SignalError::InvalidSignal);
    }
    let target = pgrp as u32;
    let mut sent_any = false;
    for pcb in get_process_table().get_all_processes() {
        if pcb.pgid.load(Ordering::Relaxed) != target {
            continue;
        }
        if send_signal(pcb.pid, signo).is_ok() {
            sent_any = true;
        }
    }
    if sent_any {
        Ok(())
    } else {
        Err(SignalError::ProcessNotFound)
    }
}
