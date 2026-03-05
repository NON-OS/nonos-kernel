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

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;
use x86_64::VirtAddr;
use lazy_static::lazy_static;

use super::constants::*;
use super::types::{MadtIso, MadtNmi};

#[derive(Clone, Copy)]
pub(crate) struct IoApicChip {
    pub gsi_base: u32,
    pub redirs: u32,
    pub mmio: VirtAddr,
}

pub(crate) static INITIALIZED: AtomicBool = AtomicBool::new(false);
pub(crate) static IOAPICS: Mutex<[Option<IoApicChip>; MAX_IOAPIC]> = Mutex::new([None; MAX_IOAPIC]);
pub(crate) static COUNT: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct IsoCache {
    pub iso: smallvec::SmallVec<[MadtIso; 16]>,
    pub nmis: smallvec::SmallVec<[MadtNmi; 8]>,
}

lazy_static! {
    pub(crate) static ref ISO: Mutex<IsoCache> = Mutex::new(IsoCache {
        iso: smallvec::SmallVec::new(),
        nmis: smallvec::SmallVec::new(),
    });
    pub(crate) static ref MSI_CLAIMED: Mutex<bitvec::vec::BitVec> =
        Mutex::new(bitvec::vec::BitVec::repeat(false, MAX_GSI));
}

pub(crate) static VEC_ALLOC: Mutex<VecAlloc> = Mutex::new(VecAlloc::new());

pub(crate) struct VecAlloc {
    next: u8,
    reserved: [bool; 256],
}

impl VecAlloc {
    pub(crate) const fn new() -> Self {
        Self { next: VEC_MIN, reserved: [false; 256] }
    }

    pub(crate) fn reserve(&mut self, v: u8) {
        self.reserved[v as usize] = true;
    }

    pub(crate) fn alloc(&mut self) -> Option<u8> {
        for _ in 0..200 {
            let v = self.next;
            self.next = if self.next >= VEC_MAX { VEC_MIN } else { self.next + 1 };
            if v >= VEC_MIN && v <= VEC_MAX && !self.reserved[v as usize] {
                self.reserved[v as usize] = true;
                return Some(v);
            }
        }
        None
    }

    pub(crate) fn free(&mut self, v: u8) {
        if v >= VEC_MIN && v <= VEC_MAX {
            self.reserved[v as usize] = false;
        }
    }
}

#[inline]
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

#[inline]
pub fn count() -> usize {
    COUNT.load(Ordering::Acquire)
}
