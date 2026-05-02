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

use super::core::SignalState;

impl SignalState {
    /// Snapshot the current blocked mask so a later sigreturn can
    /// restore it. Used by `sigsuspend` to retain the original mask
    /// across the temporary suspended mask + handler delivery.
    pub fn save_blocked_for_suspend(&mut self) {
        self.saved_mask = Some(self.blocked.load(Ordering::Acquire));
    }

    /// Consume the saved mask if any. The sigreturn path uses this to
    /// override the sigframe's saved_blocked when sigsuspend was the
    /// origin of the handler frame.
    pub fn take_saved_mask(&mut self) -> Option<u64> {
        self.saved_mask.take()
    }
}
