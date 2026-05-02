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
    pub fn next_pending_unblocked(&self) -> Option<u8> {
        let deliverable =
            self.pending.load(Ordering::Acquire) & !self.blocked.load(Ordering::Acquire);
        if deliverable == 0 {
            return None;
        }
        for signo in 1..SIG_COUNT as u8 {
            if deliverable & mask_of(signo) != 0 {
                return Some(signo);
            }
        }
        None
    }

    pub fn has_pending_signals(&self) -> bool {
        self.pending.load(Ordering::Acquire) & !self.blocked.load(Ordering::Acquire) != 0
    }
}
