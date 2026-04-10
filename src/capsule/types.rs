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

pub type CapsuleId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsuleState {
    Loaded,
    Running,
    Suspended,
    Exited(i32),
    Faulted,
}

#[derive(Debug, Clone)]
pub struct Capsule {
    pub id: CapsuleId,
    pub manifest_id: [u8; 32],
    pub state: CapsuleState,
    pub pid: Option<u64>,
    pub caps: u64,
    pub unlock: [u8; 32],
}

impl Capsule {
    pub fn new(id: CapsuleId, manifest_id: [u8; 32], unlock: [u8; 32], caps: u64) -> Self {
        Self { id, manifest_id, state: CapsuleState::Loaded, pid: None, caps, unlock }
    }

    pub fn has_cap(&self, cap: u64) -> bool {
        self.caps & cap != 0
    }
}
