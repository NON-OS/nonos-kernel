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

pub(super) static VM_UNIFIED_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init_unified_vm() -> Result<(), &'static str> {
    if VM_UNIFIED_INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    // The canonical paging manager is initialised on first use via its
    // own `init` path; the previously parallel virt/virtual_memory
    // bring-up is gone. This entry point stays so the boot sequence
    // can record that unified VM init has run.
    Ok(())
}
