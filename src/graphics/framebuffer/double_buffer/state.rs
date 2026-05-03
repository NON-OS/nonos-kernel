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

use crate::display::framebuffer::dimensions;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub(super) static DOUBLE_BUFFER_ENABLED: AtomicBool = AtomicBool::new(false);
pub(super) static BACK_BUFFER_PTR: AtomicUsize = AtomicUsize::new(0);
pub(super) static BACK_BUFFER_SIZE: AtomicUsize = AtomicUsize::new(0);

static mut BACK_BUFFER: Option<Vec<u32>> = None;

pub fn init_double_buffer() -> bool {
    let (width, height) = dimensions();
    if width == 0 || height == 0 {
        return false;
    }
    let size = (width as usize) * (height as usize);
    unsafe {
        BACK_BUFFER = Some(alloc::vec![0u32; size]);
        if let Some(ref buf) = BACK_BUFFER {
            BACK_BUFFER_PTR.store(buf.as_ptr() as usize, Ordering::SeqCst);
            BACK_BUFFER_SIZE.store(size, Ordering::SeqCst);
            DOUBLE_BUFFER_ENABLED.store(true, Ordering::SeqCst);
            return true;
        }
    }
    false
}

pub fn is_enabled() -> bool {
    DOUBLE_BUFFER_ENABLED.load(Ordering::Relaxed)
}

pub fn enable() {
    if BACK_BUFFER_PTR.load(Ordering::Relaxed) != 0 {
        DOUBLE_BUFFER_ENABLED.store(true, Ordering::SeqCst);
    }
}

pub fn disable() {
    DOUBLE_BUFFER_ENABLED.store(false, Ordering::SeqCst);
}

pub fn get_back_buffer_ptr() -> *mut u32 {
    BACK_BUFFER_PTR.load(Ordering::Relaxed) as *mut u32
}
