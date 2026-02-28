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

use core::ptr::addr_of_mut;
use core::sync::atomic::Ordering;
use super::super::constants::MAX_CONSOLES;
use super::super::cursor::{enable_cursor, update_cursor};
use super::super::error::VgaError;
use super::super::state::{CONSOLES, INITIALIZED, PANIC_MODE};

pub fn init() -> Result<(), VgaError> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(VgaError::AlreadyInitialized);
    }

    // SAFETY: Single-threaded initialization, using addr_of_mut! to avoid creating references to mutable static
    unsafe {
        let consoles = addr_of_mut!(CONSOLES);
        for i in 0..MAX_CONSOLES {
            (*consoles)[i].clear();
        }
    }

    enable_cursor(14, 15);

    // SAFETY: Single-threaded initialization
    unsafe {
        let consoles = addr_of_mut!(CONSOLES);
        (*consoles)[0].flush_to_vga();
    }

    update_cursor(0, 0);

    Ok(())
}

#[inline]
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

pub fn enter_panic_mode() {
    PANIC_MODE.store(true, Ordering::Release);
}
