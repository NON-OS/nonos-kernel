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

use super::super::capability::gate_call;
use super::super::error::DriverNvmeError;
use super::super::protocol::{encode_request, OP_SMART_HEALTH};
use super::seq::next_request_id;
use super::smart_decode;
use super::status_map::lift;
use super::transport::round_trip;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvmeSmartHealth {
    pub critical_warning: u8,
    pub temperature_kelvin: u16,
    pub temperature_celsius: i16,
    pub available_spare: u8,
    pub available_spare_threshold: u8,
    pub percentage_used: u8,
    pub endurance_group_warning: u8,
    pub data_units_read: u128,
    pub data_units_written: u128,
    pub host_read_commands: u128,
    pub host_write_commands: u128,
    pub controller_busy_time: u128,
    pub power_cycles: u128,
    pub power_on_hours: u128,
    pub unsafe_shutdowns: u128,
    pub media_errors: u128,
    pub error_log_entries: u128,
    pub warning_temp_time: u32,
    pub critical_temp_time: u32,
}

pub fn smart_health() -> Result<NvmeSmartHealth, DriverNvmeError> {
    let _caller = gate_call()?;
    let request_id = next_request_id();
    let frame = encode_request(OP_SMART_HEALTH, 0, request_id, &[]);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(lift(resp.status));
    }
    smart_decode::decode(&resp.body)
}
