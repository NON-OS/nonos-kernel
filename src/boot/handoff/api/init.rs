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

use core::mem::size_of;

use super::super::types::{flags, BootHandoffV1, HANDOFF_MAGIC, HANDOFF_VERSION};
use super::error::HandoffError;
use super::query::BOOT_HANDOFF;

// Embedded raw-phys pointers (fb, mmap, ACPI RSDP) still travel as
// physical addresses on x86_64; the kernel resolves them through
// the directmap. The 48-bit ceiling is a sanity guard against a
// truncated or wildly bogus value.
const MAX_PHYS_PTR: u64 = 0x0000_FFFF_FFFF_FFFF;
const HANDOFF_ALIGNMENT: u64 = 8;

// The handoff struct pointer itself is a canonical virtual address
// in the new kernel address space. Bootloader passes
// DIRECTMAP_BASE + handoff_phys so the read survives once PML4[0]
// is torn down.
fn is_canonical(addr: u64) -> bool {
    let upper = addr >> 47;
    upper == 0 || upper == 0x1FFFF
}

pub unsafe fn init_handoff(ptr: u64) -> Result<&'static BootHandoffV1, HandoffError> {
    if ptr == 0 || ptr % HANDOFF_ALIGNMENT != 0 || !is_canonical(ptr) {
        return Err(HandoffError::NullPointer);
    }

    let handoff = unsafe { &*(ptr as *const BootHandoffV1) };

    if handoff.magic != HANDOFF_MAGIC {
        return Err(HandoffError::InvalidMagic);
    }

    if handoff.version != HANDOFF_VERSION {
        return Err(HandoffError::VersionMismatch {
            expected: HANDOFF_VERSION,
            got: handoff.version,
        });
    }

    let expected_size = size_of::<BootHandoffV1>() as u16;
    if handoff.size != expected_size {
        return Err(HandoffError::SizeMismatch { expected: expected_size, got: handoff.size });
    }

    validate_pointers(handoff)?;

    if BOOT_HANDOFF.get().is_some() {
        return Err(HandoffError::AlreadyInitialized);
    }

    BOOT_HANDOFF.call_once(|| handoff);
    Ok(handoff)
}

fn validate_pointers(handoff: &BootHandoffV1) -> Result<(), HandoffError> {
    if handoff.has_flag(flags::FB_AVAILABLE) && handoff.fb.ptr > MAX_PHYS_PTR {
        return Err(HandoffError::InvalidData);
    }
    if handoff.mmap.ptr != 0 && handoff.mmap.ptr > MAX_PHYS_PTR {
        return Err(HandoffError::InvalidData);
    }
    if handoff.has_flag(flags::ACPI_AVAILABLE) && handoff.acpi.rsdp > MAX_PHYS_PTR {
        return Err(HandoffError::InvalidData);
    }
    Ok(())
}
