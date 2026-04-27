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

use super::super::{paging, secure_memory as memory, virt, virtual_memory};
use core::sync::atomic::{AtomicBool, Ordering};

pub(super) static VM_UNIFIED_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init_unified_vm() -> Result<(), &'static str> {
    if VM_UNIFIED_INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    let cr3 = paging::get_current_cr3();
    virt::init(cr3).map_err(|_| "Failed to init virt")?;
    virtual_memory::init().map_err(|_| "Failed to init virtual_memory")?;
    memory::init().map_err(|_| "Failed to init memory")?;

    crate::log_info!("Unified VM subsystem initialized");
    Ok(())
}
