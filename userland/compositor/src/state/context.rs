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

use super::{DamageAccumulator, FocusTable, SceneTable};

// Owned by the runner. Single-thread today so plain mutable refs
// suffice; once render workers fan out, scene + damage move behind
// a sequence-locked snapshot owned by the scene worker.
pub struct Context {
    pub gfx_pid: u32,
    pub resource_id: u32,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub backing_va: u64,
    pub primary_handle: u64,
    pub first_scanout_done: bool,
    pub next_request_id: u32,
    pub scene: SceneTable,
    pub damage: DamageAccumulator,
    pub focus: FocusTable,
}

impl Context {
    pub fn issue_request_id(&mut self) -> u32 {
        let id = self.next_request_id;
        self.next_request_id = id.wrapping_add(1).max(1);
        id
    }
}
