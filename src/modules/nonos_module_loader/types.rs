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


extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use crate::syscall::capabilities::CapabilityToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NonosModuleType {
    System = 0,
    Application = 1,
    Driver = 2,
    Service = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NonosModuleState {
    Unloaded = 0,
    Loading = 1,
    Loaded = 2,
    Running = 3,
    Paused = 4,
    Stopping = 5,
    Stopped = 6,
    Failed = 7,
}

#[derive(Debug)]
pub struct NonosLoadedModule {
    pub module_id: u64,
    pub name: String,
    pub module_type: NonosModuleType,
    pub state: NonosModuleState,
    pub code: Vec<u8>,
    pub entry_point: Option<u64>,
    pub memory_base: Option<u64>,
    pub memory_size: usize,
    pub capabilities: Vec<CapabilityToken>,
    pub signature_verified: bool,
    pub hash: [u8; 32],
    pub load_time: u64,
}

#[derive(Debug)]
pub struct NonosModuleInfo {
    pub module_id: u64,
    pub name: String,
    pub module_type: NonosModuleType,
    pub state: NonosModuleState,
    pub memory_size: usize,
    pub signature_verified: bool,
    pub hash: [u8; 32],
    pub load_time: u64,
    pub capabilities_count: usize,
}
