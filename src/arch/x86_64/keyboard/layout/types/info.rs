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

use super::layout::Layout;
use super::dead_key::DeadKey;

#[derive(Debug, Clone, Copy)]
pub struct LayoutInfo {
    pub layout: Layout,
    pub base: &'static [u8; 128],
    pub shift: &'static [u8; 128],
    pub altgr: &'static [u8; 128],
    pub dead_keys_base: &'static [(u8, DeadKey)],
    pub dead_keys_shift: &'static [(u8, DeadKey)],
}

impl LayoutInfo {
    pub const fn new(
        layout: Layout,
        base: &'static [u8; 128],
        shift: &'static [u8; 128],
        altgr: &'static [u8; 128],
    ) -> Self {
        Self {
            layout,
            base,
            shift,
            altgr,
            dead_keys_base: &[],
            dead_keys_shift: &[],
        }
    }

    pub const fn with_dead_keys(
        layout: Layout,
        base: &'static [u8; 128],
        shift: &'static [u8; 128],
        altgr: &'static [u8; 128],
        dead_base: &'static [(u8, DeadKey)],
        dead_shift: &'static [(u8, DeadKey)],
    ) -> Self {
        Self {
            layout,
            base,
            shift,
            altgr,
            dead_keys_base: dead_base,
            dead_keys_shift: dead_shift,
        }
    }

    pub fn lookup(&self, scan_code: u8, shifted: bool, altgr: bool) -> u8 {
        if scan_code >= 128 {
            return 0;
        }
        let idx = scan_code as usize;
        if altgr && self.altgr[idx] != 0 {
            self.altgr[idx]
        } else if shifted {
            self.shift[idx]
        } else {
            self.base[idx]
        }
    }

    pub fn is_dead_key(&self, scan_code: u8, shifted: bool) -> Option<DeadKey> {
        let table = if shifted { self.dead_keys_shift } else { self.dead_keys_base };
        for &(sc, dk) in table {
            if sc == scan_code {
                return Some(dk);
            }
        }
        None
    }
}
