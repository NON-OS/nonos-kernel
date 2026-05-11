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

use super::super::super::types::BootHandoffV1;
use super::super::error::HandoffError;
use crate::memory::layout::constants::{CANONICAL_LOW_MAX, KERNEL_BASE};

// Upper bound on the loaded NØNOS kernel image. The linker pins the
// image at KERNEL_BASE; the 256 MiB window rejects an entry_point
// the bootloader fabricated outside any plausible NØNOS layout.
pub(super) const KERNEL_IMAGE_WINDOW: u64 = 0x1000_0000;
pub(super) const MIN_LOADER_ENTRY: u64 = 0x10_0000;

pub(super) fn check(handoff: &BootHandoffV1) -> Result<(), HandoffError> {
    let entry = handoff.entry_point;
    let upper_max = KERNEL_BASE.saturating_add(KERNEL_IMAGE_WINDOW);
    let in_upper_window = entry >= KERNEL_BASE && entry < upper_max;
    let in_low_window = entry >= MIN_LOADER_ENTRY && entry <= CANONICAL_LOW_MAX;
    if !in_upper_window && !in_low_window {
        return Err(HandoffError::EntryPointOutOfRange);
    }
    Ok(())
}
