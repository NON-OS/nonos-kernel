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

use super::fadt_struct::Fadt;

impl Fadt {
    pub fn dsdt_address(&self) -> u64 {
        if self.header.length >= 148 && self.x_dsdt != 0 { self.x_dsdt } else { self.dsdt as u64 }
    }
    pub fn firmware_control_address(&self) -> u64 {
        if self.header.length >= 140 && self.x_firmware_ctrl != 0 { self.x_firmware_ctrl }
        else { self.firmware_ctrl as u64 }
    }
    pub fn pm1a_event_address(&self) -> u64 {
        if self.header.length >= 172 && self.x_pm1a_event_block.is_valid() { self.x_pm1a_event_block.address }
        else { self.pm1a_event_block as u64 }
    }
    pub fn pm1b_event_address(&self) -> u64 {
        if self.header.length >= 184 && self.x_pm1b_event_block.is_valid() { self.x_pm1b_event_block.address }
        else { self.pm1b_event_block as u64 }
    }
    pub fn pm1a_control_address(&self) -> u64 {
        if self.header.length >= 196 && self.x_pm1a_control_block.is_valid() { self.x_pm1a_control_block.address }
        else { self.pm1a_control_block as u64 }
    }
    pub fn pm1b_control_address(&self) -> u64 {
        if self.header.length >= 208 && self.x_pm1b_control_block.is_valid() { self.x_pm1b_control_block.address }
        else { self.pm1b_control_block as u64 }
    }
    pub fn pm_timer_address(&self) -> u64 {
        if self.header.length >= 232 && self.x_pm_timer_block.is_valid() { self.x_pm_timer_block.address }
        else { self.pm_timer_block as u64 }
    }
    pub fn gpe0_address(&self) -> u64 {
        if self.header.length >= 244 && self.x_gpe0_block.is_valid() { self.x_gpe0_block.address }
        else { self.gpe0_block as u64 }
    }
    pub fn gpe1_address(&self) -> u64 {
        if self.header.length >= 256 && self.x_gpe1_block.is_valid() { self.x_gpe1_block.address }
        else { self.gpe1_block as u64 }
    }
}
