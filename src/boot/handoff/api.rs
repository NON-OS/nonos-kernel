// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
use spin::Once;

use super::types::{BootHandoffV1, HANDOFF_MAGIC, HANDOFF_VERSION};

static BOOT_HANDOFF: Once<&'static BootHandoffV1> = Once::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffError {
    NullPointer,
    InvalidMagic,
    VersionMismatch { expected: u16, got: u16 },
    SizeMismatch { expected: u16, got: u16 },
    AlreadyInitialized,
}

impl HandoffError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NullPointer => "Null handoff pointer",
            Self::InvalidMagic => "Invalid handoff magic value",
            Self::VersionMismatch { .. } => "Handoff version mismatch",
            Self::SizeMismatch { .. } => "Handoff size mismatch",
            Self::AlreadyInitialized => "Handoff already initialized",
        }
    }
}

impl core::fmt::Display for HandoffError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::VersionMismatch { expected, got } => {
                write!(
                    f,
                    "Handoff version mismatch: expected {}, got {}",
                    expected, got
                )
            }
            Self::SizeMismatch { expected, got } => {
                write!(
                    f,
                    "Handoff size mismatch: expected {}, got {}",
                    expected, got
                )
            }
            _ => write!(f, "{}", self.as_str()),
        }
    }
}
/// # Safety {
/// Must be called exactly once during early boot
/// ptr must point to a valid BootHandoffV1 structure
/// The memory must remain valid for the kernel lifetime
/// ptr must be properly aligned for BootHandoffV1
/// }
pub unsafe fn init_handoff(ptr: u64) -> Result<&'static BootHandoffV1, HandoffError> {
    const MAX_HANDOFF_PTR: u64 = 0x0000_FFFF_FFFF_FFFF; // Max physical address
    const HANDOFF_ALIGNMENT: u64 = 8; // Required alignment
    if ptr == 0 {
        return Err(HandoffError::NullPointer);
    }

    if ptr > MAX_HANDOFF_PTR {
        return Err(HandoffError::NullPointer);
    }

    if ptr % HANDOFF_ALIGNMENT != 0 {
        return Err(HandoffError::NullPointer);
    }

    // # SAFETY: Caller guarantees ptr points to valid BootHandoffV1
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
        return Err(HandoffError::SizeMismatch {
            expected: expected_size,
            got: handoff.size,
        });
    }

    if handoff.has_flag(super::types::flags::FB_AVAILABLE) {
        if handoff.fb.ptr > MAX_HANDOFF_PTR {
            return Err(HandoffError::InvalidMagic); 
        }
    }

    if handoff.mmap.ptr != 0 && handoff.mmap.ptr > MAX_HANDOFF_PTR {
        return Err(HandoffError::InvalidMagic);
    }

    if handoff.has_flag(super::types::flags::ACPI_AVAILABLE) {
        if handoff.acpi.rsdp > MAX_HANDOFF_PTR {
            return Err(HandoffError::InvalidMagic);
        }
    }

    if BOOT_HANDOFF.get().is_some() {
        return Err(HandoffError::AlreadyInitialized);
    }

    BOOT_HANDOFF.call_once(|| handoff);
    Ok(handoff)
}

#[inline]
pub fn get_handoff() -> Option<&'static BootHandoffV1> {
    BOOT_HANDOFF.get().copied()
}

#[inline]
pub fn is_initialized() -> bool {
    BOOT_HANDOFF.get().is_some()
}

pub fn total_memory() -> u64 {
    get_handoff()
        .map(|h| unsafe { h.mmap.total_usable_memory() })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    #[test]
    fn test_error_display() {
        let e = HandoffError::NullPointer;
        assert_eq!(e.as_str(), "Null handoff pointer");

        let e = HandoffError::VersionMismatch {
            expected: 1,
            got: 2,
        };
        let s = alloc::format!("{}", e);
        assert!(s.contains("1"));
        assert!(s.contains("2"));
    }
}
