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

static DEAD: AtomicBool = AtomicBool::new(false);

/* The transport error `vfs::call` raises when the endpoint answers nothing;
 * the kernel bounds that at a 5 s timeout. Anything else is a live server
 * refusing or missing a file, which must not latch the store off. */
const TRANSPORT: &str = "vfs ipc failed";

/// False once the file server has failed to answer at all.
pub fn live() -> bool {
    !DEAD.load(Ordering::Relaxed)
}

/// Latches the store off after a transport failure, so one dead-VFS round
/// trip is the whole cost rather than one per save.
pub fn note(err: &'static str) {
    if err == TRANSPORT {
        DEAD.store(true, Ordering::Relaxed);
    }
}
