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
//! Per-process alarm tick.
//!
//! The trusted timer IRQ walks the process table every N ticks and
//! delivers `SIGALRM` to any PCB whose `alarm_time_ms` has expired.
//! The walk lives here in `process::` so the timer IRQ owns its own
//! delivery path and does not reach across into a syscall module.

use crate::syscall::signals::constants::SIGALRM;
use crate::syscall::signals::delivery::send_signal;

/// Walk the process table and deliver `SIGALRM` to any PCB whose
/// alarm timestamp has expired. Intended to be called from the
/// kernel timer IRQ tick.
pub fn tick() {
    for pcb in crate::process::get_process_table().get_all_processes() {
        if pcb.check_alarm_expired() {
            let _ = send_signal(pcb.pid, SIGALRM);
        }
    }
}
