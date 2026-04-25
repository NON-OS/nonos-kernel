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

use super::super::error::NvmeError;
use super::handler::nvme_isr;
use crate::drivers::pci::PciDevice;
use crate::interrupts::{allocate_vector, free_vector, register_interrupt_handler};
use core::sync::atomic::{AtomicU8, Ordering};

static ALLOCATED_VECTOR: AtomicU8 = AtomicU8::new(0);

pub fn setup_msix_interrupt(pci: &mut PciDevice) -> Result<u8, NvmeError> {
    let vector = allocate_vector().ok_or(NvmeError::InterruptAllocationFailed)?;
    register_interrupt_handler(vector, nvme_isr)
        .map_err(|_| NvmeError::InterruptAllocationFailed)?;
    pci.configure_msix(vector).map_err(|_| {
        let _ = free_vector(vector);
        NvmeError::MsixConfigurationFailed
    })?;
    ALLOCATED_VECTOR.store(vector, Ordering::Release);
    Ok(vector)
}

pub fn teardown_interrupt() {
    let vector = ALLOCATED_VECTOR.swap(0, Ordering::AcqRel);
    if vector != 0 {
        let _ = crate::interrupts::unregister_handler(vector);
        let _ = free_vector(vector);
    }
}

pub fn get_allocated_vector() -> Option<u8> {
    let v = ALLOCATED_VECTOR.load(Ordering::Acquire);
    if v != 0 {
        Some(v)
    } else {
        None
    }
}
