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

use core::sync::atomic::Ordering;

use super::core::{mask_of, SignalState};

impl SignalState {
    pub fn is_pending(&self, signo: u8) -> bool {
        self.pending.load(Ordering::Acquire) & mask_of(signo) != 0
    }

    pub fn is_blocked(&self, signo: u8) -> bool {
        self.blocked.load(Ordering::Acquire) & mask_of(signo) != 0
    }

    pub fn set_pending(&self, signo: u8) {
        self.pending.fetch_or(mask_of(signo), Ordering::AcqRel);
    }

    pub fn clear_pending(&self, signo: u8) {
        self.pending.fetch_and(!mask_of(signo), Ordering::AcqRel);
    }

    pub fn set_blocked(&self, signo: u8) {
        self.blocked.fetch_or(mask_of(signo), Ordering::AcqRel);
    }

    pub fn clear_blocked(&self, signo: u8) {
        self.blocked.fetch_and(!mask_of(signo), Ordering::AcqRel);
    }

    pub fn get_pending_mask(&self) -> u64 {
        self.pending.load(Ordering::Acquire)
    }

    pub fn get_blocked_mask(&self) -> u64 {
        self.blocked.load(Ordering::Acquire)
    }

    pub fn set_blocked_mask(&self, mask: u64) {
        self.blocked.store(mask, Ordering::Release);
    }
}
