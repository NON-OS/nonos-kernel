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

//! Decoded raster bytes held by every tab's image store together.
//!
//! Each store keeps its own rasters under `BYTE_BUDGET`, but the stores of
//! six tabs could each fill theirs, past what the heap holds beside the
//! pages themselves. Every store charges what it keeps here and refunds what
//! it drops, and none may take the process past `PROCESS_BUDGET`. The host
//! proofs run tests side by side, so there each thread keeps its own count.

/// Ceiling on decoded rasters across every store in the process.
pub(crate) const PROCESS_BUDGET: usize = 32 * 1024 * 1024;

#[cfg(not(feature = "harness"))]
static HELD: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

#[cfg(feature = "harness")]
std::thread_local!(static HELD: core::cell::Cell<usize> = const { core::cell::Cell::new(0) });

/// Raster bytes every store holds now.
#[cfg(not(feature = "harness"))]
pub fn held() -> usize {
    HELD.load(core::sync::atomic::Ordering::Relaxed)
}

#[cfg(feature = "harness")]
pub fn held() -> usize {
    HELD.with(|h| h.get())
}

#[cfg(not(feature = "harness"))]
fn set(n: usize) {
    HELD.store(n, core::sync::atomic::Ordering::Relaxed);
}

#[cfg(feature = "harness")]
fn set(n: usize) {
    HELD.with(|h| h.set(n));
}

/// A store keeps `n` more bytes.
pub(super) fn charge(n: usize) {
    set(held().saturating_add(n));
}

/// A store let `n` bytes go.
pub(super) fn refund(n: usize) {
    set(held().saturating_sub(n));
}
