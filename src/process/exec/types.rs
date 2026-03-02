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

use alloc::vec::Vec;

pub type NonosExecPid = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonosExecState {
    Ready,
    Running,
    Suspended,
    Terminated,
}

#[derive(Debug, Clone)]
pub struct NonosExecContext {
    pub pid: NonosExecPid,
    pub state: NonosExecState,
    pub entry_point: u64,
    pub created_ms: u64,
}

#[derive(Debug)]
pub struct NonosExecCreate {
    pub executable_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct NonosExecStats {
    pub active_processes: usize,
    pub total_created: u64,
    pub total_terminated: u64,
}
