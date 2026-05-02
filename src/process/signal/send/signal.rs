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

use super::info::send_signal_info;
use crate::process::signal::constants::SIG_COUNT;
use crate::process::signal::error::SignalError;
use crate::process::signal::siginfo::SigInfo;
use crate::process::{current_pid, current_uid};

pub fn send_signal(target_pid: u32, signo: u32) -> Result<(), SignalError> {
    if signo == 0 || signo as usize >= SIG_COUNT {
        return Err(SignalError::InvalidSignal);
    }
    let signo = signo as u8;
    let info = SigInfo::new_user(signo, current_pid().unwrap_or(0), current_uid());
    send_signal_info(target_pid, signo, info)
}
