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

use alloc::string::String;
use alloc::vec::Vec;

pub const PATH_MAX_BYTES: usize = 4096;
pub const ARGS_MAX_COUNT: usize = 128;
pub const ARGS_MAX_TOTAL_BYTES: usize = 32 * 1024; // 32 KiB

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NoxPid(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoxState {
    Ready,
    Running,
    Suspended,
    Migrating { from_node: u16, to_node: u16 },
    Terminated(i32),
}

#[derive(Debug, Clone)]
pub struct NoxProcess {
    pub pid: NoxPid,
    pub executable_path: String,
    pub args: Vec<String>,
    pub state: NoxState,
    pub created_ns: u64,
    pub parent: Option<NoxPid>,
    pub node: u16,                      // current placement node
    pub pending_migration_to: Option<u16>,
}

impl NoxProcess {
    #[inline]
    pub fn can_transition(from: NoxState, to: NoxState) -> bool {
        use NoxState::*;
        match (from, to) {
            (Terminated(_), _) => false,                 // terminal state
            (_, Terminated(_)) => true,                  // anything can terminate
            (Ready, Running) | (Running, Suspended) | (Suspended, Ready) => true,
            (Ready, Suspended) | (Suspended, Running) => true,
            (Running, Ready) => true,
            (Migrating { .. }, Ready) => true,
            (Ready, Migrating { .. }) | (Running, Migrating { .. }) | (Suspended, Migrating { .. }) => true,
            // No direct transitions between distinct Migrating states
            (Migrating { .. }, Migrating { .. }) => false,
            // Same state transitions (no-op but allowed)
            (Ready, Ready) | (Running, Running) | (Suspended, Suspended) => true,
            // Migration to runtime states
            (Migrating { .. }, Running) | (Migrating { .. }, Suspended) => true,
        }
    }
}
