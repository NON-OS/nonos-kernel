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

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct FocusedRef {
    pub owner_pid: u32,
    pub window_id: u32,
}

pub struct FocusModel {
    focused: Option<FocusedRef>,
}

impl FocusModel {
    pub const fn new() -> Self {
        Self { focused: None }
    }

    pub fn set(&mut self, owner_pid: u32, window_id: u32) -> bool {
        let next = FocusedRef { owner_pid, window_id };
        if self.focused == Some(next) {
            return false;
        }
        self.focused = Some(next);
        true
    }

    pub fn clear(&mut self) -> bool {
        let was_set = self.focused.is_some();
        self.focused = None;
        was_set
    }

    pub fn current(&self) -> Option<FocusedRef> {
        self.focused
    }
}
