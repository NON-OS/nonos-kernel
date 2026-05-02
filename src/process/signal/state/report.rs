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
use crate::process::signal::constants::SIG_COUNT;

impl SignalState {
    pub fn pending_bits(&self) -> u64 {
        self.pending.load(Ordering::Acquire)
    }

    pub fn shared_pending_bits(&self) -> u64 {
        self.pending.load(Ordering::Acquire)
    }

    pub fn blocked_bits(&self) -> u64 {
        self.blocked.load(Ordering::Acquire)
    }

    pub fn ignored_bits(&self) -> u64 {
        let mut bits = 0u64;
        for signo in 1..SIG_COUNT as u8 {
            if self.actions[signo as usize].is_ignored() {
                bits |= mask_of(signo);
            }
        }
        bits
    }

    pub fn caught_bits(&self) -> u64 {
        let mut bits = 0u64;
        for signo in 1..SIG_COUNT as u8 {
            if self.actions[signo as usize].is_handler() {
                bits |= mask_of(signo);
            }
        }
        bits
    }
}
