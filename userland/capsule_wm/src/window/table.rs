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

use super::Window;

pub const MAX_WINDOWS: usize = 256;

pub struct WindowTable {
    entries: [Window; MAX_WINDOWS],
}

impl WindowTable {
    pub const fn new() -> Self {
        Self {
            entries: [Window {
                owner_pid: 0,
                window_id: 0,
                rect: crate::geometry::Rect { x: 0, y: 0, width: 0, height: 0 },
                kind: super::Kind::Normal,
                visibility: super::Visibility::Hidden,
                z: 0,
                in_use: false,
            }; MAX_WINDOWS],
        }
    }

    pub fn insert(&mut self, window: Window) -> Result<(), ()> {
        if self.find(window.owner_pid, window.window_id).is_some() {
            return Err(());
        }
        for slot in self.entries.iter_mut() {
            if !slot.in_use {
                *slot = window;
                return Ok(());
            }
        }
        Err(())
    }

    pub fn find(&self, owner_pid: u32, window_id: u32) -> Option<&Window> {
        self.entries.iter().find(|w| w.matches(owner_pid, window_id))
    }

    pub fn find_mut(&mut self, owner_pid: u32, window_id: u32) -> Option<&mut Window> {
        self.entries.iter_mut().find(|w| w.matches(owner_pid, window_id))
    }

    pub fn remove(&mut self, owner_pid: u32, window_id: u32) -> Option<Window> {
        for slot in self.entries.iter_mut() {
            if slot.matches(owner_pid, window_id) {
                let copy = *slot;
                *slot = Window::default();
                return Some(copy);
            }
        }
        None
    }

    pub fn windows(&self) -> impl Iterator<Item = &Window> {
        self.entries.iter().filter(|w| w.in_use)
    }
}
