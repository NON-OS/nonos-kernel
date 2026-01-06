// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::memory::layout;
use super::constants::*;
#[derive(Debug)]
pub struct Kaslr {
    pub slide: u64,
    pub entropy_hash: [u8; 32],
    pub boot_nonce: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub align: u64,
    pub window_bytes: u64,
    pub min_slide: u64,
    pub max_slide: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            align: layout::PAGE_SIZE as u64,
            window_bytes: DEFAULT_WINDOW_SIZE,
            min_slide: MIN_SLIDE,
            max_slide: MAX_SLIDE,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Range {
    pub lo: u64,
    pub hi: u64,
}

impl Range {
    pub const fn new(lo: u64, hi: u64) -> Self { Self { lo, hi } }
    #[inline]
    pub const fn contains(&self, x: u64) -> bool { x >= self.lo && x < self.hi }
    pub const fn size(&self) -> u64 { if self.hi > self.lo { self.hi - self.lo } else { 0 } }
}
