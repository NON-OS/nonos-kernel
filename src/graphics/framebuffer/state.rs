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

use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};

pub(crate) static FB_ADDR: AtomicU64 = AtomicU64::new(0);
pub(crate) static FB_WIDTH: AtomicU32 = AtomicU32::new(0);
pub(crate) static FB_HEIGHT: AtomicU32 = AtomicU32::new(0);
pub(crate) static FB_PITCH: AtomicU32 = AtomicU32::new(0);

pub fn init(addr: u64, width: u32, height: u32, stride: u32) {
    FB_ADDR.store(addr, Ordering::SeqCst);
    FB_WIDTH.store(width, Ordering::SeqCst);
    FB_HEIGHT.store(height, Ordering::SeqCst);
    FB_PITCH.store(stride * 4, Ordering::SeqCst);
}

pub(crate) fn dimensions() -> (u32, u32) {
    (FB_WIDTH.load(Ordering::Relaxed), FB_HEIGHT.load(Ordering::Relaxed))
}
