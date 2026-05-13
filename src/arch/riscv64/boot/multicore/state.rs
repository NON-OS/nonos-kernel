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

use core::sync::atomic::{AtomicU32, Ordering};

pub(super) static HARTS_ONLINE: AtomicU32 = AtomicU32::new(1);

pub fn online_hart_count() -> u32 {
    HARTS_ONLINE.load(Ordering::Acquire)
}

pub fn is_hart_online(hart: u32) -> bool {
    hart < HARTS_ONLINE.load(Ordering::Acquire)
}

pub fn wait_for_harts(count: u32) {
    while HARTS_ONLINE.load(Ordering::Acquire) < count {
        core::hint::spin_loop();
    }
}
