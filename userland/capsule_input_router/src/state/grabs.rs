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

// Exclusive input grab. One holder at a time per kind class
// (keyboard, pointer). When a grab is active every event in that
// class routes only to the holder regardless of subscription mask.

#[derive(Clone, Copy, Default)]
pub struct Grab {
    pub holder_pid: u32,
    pub kind_mask: u32,
}

pub struct GrabTable {
    keyboard: Grab,
    pointer: Grab,
}

impl GrabTable {
    pub const fn new() -> Self {
        Self {
            keyboard: Grab { holder_pid: 0, kind_mask: 0 },
            pointer: Grab { holder_pid: 0, kind_mask: 0 },
        }
    }

    pub fn request(&mut self, pid: u32, kind_mask: u32) -> bool {
        if kind_mask & 0b0000_0011 != 0 {
            if self.keyboard.holder_pid != 0 && self.keyboard.holder_pid != pid {
                return false;
            }
            self.keyboard = Grab { holder_pid: pid, kind_mask };
        }
        if kind_mask & 0b1111_1100 != 0 {
            if self.pointer.holder_pid != 0 && self.pointer.holder_pid != pid {
                return false;
            }
            self.pointer = Grab { holder_pid: pid, kind_mask };
        }
        true
    }

    pub fn release(&mut self, pid: u32) {
        if self.keyboard.holder_pid == pid {
            self.keyboard = Grab::default();
        }
        if self.pointer.holder_pid == pid {
            self.pointer = Grab::default();
        }
    }

    pub fn holder_for(&self, kind: u16) -> Option<u32> {
        let bit = 1u32.checked_shl(kind as u32).unwrap_or(0);
        if self.keyboard.kind_mask & bit != 0 {
            return Some(self.keyboard.holder_pid);
        }
        if self.pointer.kind_mask & bit != 0 {
            return Some(self.pointer.holder_pid);
        }
        None
    }
}
