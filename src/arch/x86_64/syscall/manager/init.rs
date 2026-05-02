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

use super::entry::syscall_entry_asm;
use crate::arch::x86_64::syscall::msr;

static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init() -> Result<(), &'static str> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err("syscall already initialized");
    }
    msr::setup_star(0x08, 0x10, 0x1B, 0x23);
    msr::setup_lstar(syscall_entry_asm as *const () as u64);
    msr::setup_fmask();
    msr::enable_sce();
    Ok(())
}
