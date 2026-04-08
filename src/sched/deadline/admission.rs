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

use crate::sched::task::DeadlineParams;
use super::types::{AdmissionError, MAX_DL_BANDWIDTH, MIN_DL_PERIOD};
use super::queue::get_scheduler;

pub fn can_admit(params: &DeadlineParams) -> Result<(), AdmissionError> {
    if !params.is_valid() { return Err(AdmissionError::InvalidParameters); }
    if params.period < MIN_DL_PERIOD { return Err(AdmissionError::PeriodTooShort); }
    let task_bw = params.bandwidth();
    let s = get_scheduler().lock();
    if s.total_bandwidth + task_bw > MAX_DL_BANDWIDTH {
        return Err(AdmissionError::InsufficientBandwidth);
    }
    Ok(())
}

pub fn bandwidth_utilization() -> u64 {
    let s = get_scheduler().lock();
    (s.total_bandwidth * 100) >> 20
}
