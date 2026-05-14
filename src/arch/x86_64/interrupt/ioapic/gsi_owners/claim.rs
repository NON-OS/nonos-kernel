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

use core::sync::atomic::Ordering;

use super::super::constants::MAX_GSI;
use super::super::error::{IoApicError, IoApicResult};
use super::state::{GSI_OWNERS, OWNER_CAPSULE, OWNER_FREE, OWNER_KERNEL};

// CAS Free->Kernel. Returns `Ok` only on a clean transition; refuses
// if the GSI is already owned (capsule or kernel) so the kernel side
// cannot silently steal a GSI a capsule already drives.
pub fn claim_for_kernel(gsi: u32) -> IoApicResult<()> {
    let slot = slot(gsi)?;
    GSI_OWNERS[slot]
        .compare_exchange(OWNER_FREE, OWNER_KERNEL, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|prev| match prev {
            OWNER_CAPSULE => IoApicError::GsiOwnedByCapsule,
            OWNER_KERNEL => IoApicError::GsiOwnedByKernel,
            _ => IoApicError::GsiOwnedByKernel,
        })
}

// CAS Free->Capsule. Refuses if the GSI is owned by the kernel; a
// capsule re-bind path is owned by the broker's grant table and never
// reaches this entry while the GSI is still in OWNER_CAPSULE state.
pub fn claim_for_capsule(gsi: u32) -> IoApicResult<()> {
    let slot = slot(gsi)?;
    GSI_OWNERS[slot]
        .compare_exchange(OWNER_FREE, OWNER_CAPSULE, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|prev| match prev {
            OWNER_KERNEL => IoApicError::GsiOwnedByKernel,
            OWNER_CAPSULE => IoApicError::GsiOwnedByCapsule,
            _ => IoApicError::GsiOwnedByCapsule,
        })
}

// CAS Capsule->Free, owner-checked. Used by the broker's IRQ release
// path on `MkIrqUnbind`, `MkDeviceRelease`, and process exit.
pub fn release_capsule(gsi: u32) -> IoApicResult<()> {
    let slot = slot(gsi)?;
    GSI_OWNERS[slot]
        .compare_exchange(OWNER_CAPSULE, OWNER_FREE, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| IoApicError::GsiNotOwnedByCapsule)
}

// Snapshot helper for diagnostics; not load-bearing on the bind path.
pub fn owner_of(gsi: u32) -> Option<u8> {
    let s = gsi as usize;
    if s >= MAX_GSI {
        return None;
    }
    Some(GSI_OWNERS[s].load(Ordering::Acquire))
}

#[inline]
fn slot(gsi: u32) -> IoApicResult<usize> {
    let s = gsi as usize;
    if s >= MAX_GSI {
        return Err(IoApicError::InvalidGsi);
    }
    Ok(s)
}
