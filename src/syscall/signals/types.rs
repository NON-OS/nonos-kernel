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

extern crate alloc;

use alloc::vec::Vec;
use super::constants::SIG_DFL;

#[derive(Debug, Clone, Copy, Default)]
pub struct SigSet(pub u64);

impl SigSet {
    pub const fn new() -> Self {
        SigSet(0)
    }

    pub const fn full() -> Self {
        SigSet(!0)
    }

    pub fn add(&mut self, sig: u32) {
        if sig > 0 && sig <= 64 {
            self.0 |= 1u64 << (sig - 1);
        }
    }

    pub fn remove(&mut self, sig: u32) {
        if sig > 0 && sig <= 64 {
            self.0 &= !(1u64 << (sig - 1));
        }
    }

    pub fn contains(&self, sig: u32) -> bool {
        if sig > 0 && sig <= 64 {
            (self.0 & (1u64 << (sig - 1))) != 0
        } else {
            false
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

impl core::ops::Not for SigSet {
    type Output = Self;
    fn not(self) -> Self {
        SigSet(!self.0)
    }
}

impl core::ops::BitAnd for SigSet {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        SigSet(self.0 & rhs.0)
    }
}

impl PartialEq<u64> for SigSet {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

#[derive(Debug, Clone, Copy)]
pub struct KernelSigAction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: SigSet,
}

impl Default for KernelSigAction {
    fn default() -> Self {
        KernelSigAction {
            handler: SIG_DFL,
            flags: 0,
            restorer: 0,
            mask: SigSet::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PendingSignal {
    pub signo: u32,
    pub code: i32,
    pub pid: u32,
    pub uid: u32,
    pub value: u64,
    pub timestamp: u64,
}

#[derive(Clone)]
pub struct ProcessSignalState {
    pub actions: [KernelSigAction; 65],
    pub blocked: SigSet,
    pub pending: SigSet,
    pub pending_queue: Vec<PendingSignal>,
    pub saved_mask: Option<SigSet>,
    pub alt_stack: Option<(u64, usize)>,
}

impl Default for ProcessSignalState {
    fn default() -> Self {
        ProcessSignalState {
            actions: [KernelSigAction::default(); 65],
            blocked: SigSet::new(),
            pending: SigSet::new(),
            pending_queue: Vec::new(),
            saved_mask: None,
            alt_stack: None,
        }
    }
}
