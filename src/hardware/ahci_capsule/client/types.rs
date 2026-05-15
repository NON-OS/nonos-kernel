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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AhciControllerInfo {
    pub cap: u32,
    pub ghc: u32,
    pub pi: u32,
    pub version: u32,
    pub cap2: u32,
    pub port_count: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AhciPortInfo {
    pub index: u8,
    pub implemented: bool,
    pub present: bool,
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
