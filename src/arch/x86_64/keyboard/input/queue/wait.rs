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

use core::sync::atomic::{AtomicBool, Ordering};

pub struct WaitHandle {
    notified: AtomicBool,
}

impl WaitHandle {
    pub const fn new() -> Self {
        Self {
            notified: AtomicBool::new(false),
        }
    }

    pub fn is_notified(&self) -> bool {
        self.notified.load(Ordering::Acquire)
    }

    pub fn clear(&self) {
        self.notified.store(false, Ordering::Release);
    }

    pub(crate) fn notify(&self) {
        self.notified.store(true, Ordering::Release);
    }
}

impl Default for WaitHandle {
    fn default() -> Self {
        Self::new()
    }
}
