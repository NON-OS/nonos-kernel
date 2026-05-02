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

use super::allocator::ALLOCATOR;
use crate::mem::brk;

const INITIAL_HEAP_SIZE: usize = 4 * 1024 * 1024;

static INITIALIZED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapError {
    AlreadyInitialized,
    BrkFailed,
}

/// Bind the global allocator to a 4 MiB region grown from the program
/// break. The heap is fixed at this size for the life of the process —
/// out-of-memory does not grow further; the runtime aborts via the
/// default `alloc_error_handler` (which calls our `_exit(134)`
/// panic handler).
///
/// Calling order is one-shot: the first successful call locks
/// initialisation; subsequent calls return `AlreadyInitialized`. On
/// `brk` failure the initialisation flag is released so the caller may
/// retry once the failure cause is understood — the recommended
/// production response is to abort the capsule, since a capsule that
/// cannot allocate cannot serve.
pub fn init() -> Result<(), HeapError> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(HeapError::AlreadyInitialized);
    }
    let base = brk(0);
    let target = base.saturating_add(INITIAL_HEAP_SIZE as u64);
    let actual = brk(target);
    if actual < target {
        INITIALIZED.store(false, Ordering::SeqCst);
        return Err(HeapError::BrkFailed);
    }
    // SAFETY: ek@nonos.systems — `brk` returned at least `target`, so
    // `[base, base + INITIAL_HEAP_SIZE)` is now valid heap memory owned
    // exclusively by this process. The allocator takes ownership for
    // the lifetime of the program.
    unsafe {
        ALLOCATOR.lock().init(base as *mut u8, INITIAL_HEAP_SIZE);
    }
    Ok(())
}
