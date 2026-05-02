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

use super::iter::SignalSetIter;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SignalSet {
    bits: u64,
}

impl SignalSet {
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    pub const fn full() -> Self {
        Self { bits: !0 }
    }

    pub fn add(&mut self, signo: u8) {
        if signo > 0 && signo <= 64 {
            self.bits |= 1u64 << (signo as u64);
        }
    }

    pub fn remove(&mut self, signo: u8) {
        if signo > 0 && signo <= 64 {
            self.bits &= !(1u64 << (signo as u64));
        }
    }

    pub fn contains(&self, signo: u8) -> bool {
        signo > 0 && signo <= 64 && self.bits & (1u64 << (signo as u64)) != 0
    }

    pub fn is_empty(&self) -> bool {
        self.bits == 0
    }

    pub fn as_bits(&self) -> u64 {
        self.bits
    }

    pub fn from_bits(bits: u64) -> Self {
        Self { bits }
    }

    pub fn union(&self, other: &SignalSet) -> SignalSet {
        SignalSet { bits: self.bits | other.bits }
    }

    pub fn intersection(&self, other: &SignalSet) -> SignalSet {
        SignalSet { bits: self.bits & other.bits }
    }

    pub fn difference(&self, other: &SignalSet) -> SignalSet {
        SignalSet { bits: self.bits & !other.bits }
    }

    pub fn complement(&self) -> SignalSet {
        SignalSet { bits: !self.bits }
    }

    pub fn count(&self) -> usize {
        self.bits.count_ones() as usize
    }

    pub fn first_signal(&self) -> Option<u8> {
        if self.bits == 0 {
            return None;
        }
        Some(self.bits.trailing_zeros() as u8)
    }

    pub fn iter(&self) -> SignalSetIter {
        SignalSetIter::new(*self)
    }
}
