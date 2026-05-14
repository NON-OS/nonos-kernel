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

use crate::constants::PORT_KIND_NONE;

#[derive(Debug, Clone, Copy)]
pub struct PortInfo {
    pub index: u8,
    pub implemented: u8,
    pub present: u8,
    pub kind: u8,
    pub ssts: u32,
    pub sig: u32,
    pub interrupt_status: u32,
    pub command_status: u32,
    pub task_file_data: u32,
    pub sata_error: u32,
    pub active_commands: u32,
    pub issued_commands: u32,
}

impl PortInfo {
    pub const fn empty(index: u8) -> Self {
        Self {
            index,
            implemented: 0,
            present: 0,
            kind: PORT_KIND_NONE,
            ssts: 0,
            sig: 0,
            interrupt_status: 0,
            command_status: 0,
            task_file_data: 0,
            sata_error: 0,
            active_commands: 0,
            issued_commands: 0,
        }
    }
}
