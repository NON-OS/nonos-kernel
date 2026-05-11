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

//! Pure check: a `MkMmioMap` request must not put the MSI-X table
//! or its pending-bit array into a capsule address space. The
//! kernel programs both regions on the capsule's behalf through the
//! MSI-X bind path and `MkPciConfigWrite`; exposing them via mmap
//! would let a capsule short-circuit the allowlist.

use crate::drivers::pci::constants::MSIX_ENTRY_SIZE;
use crate::drivers::pci::types::MsixInfo;

use super::types::MmioMapError;

pub fn validate(
    msix: Option<&MsixInfo>,
    bar_index: u8,
    offset: u64,
    length: u64,
) -> Result<(), MmioMapError> {
    let Some(m) = msix else { return Ok(()) };
    if bar_index == m.table_bar && overlaps(offset, length, table_region(m)) {
        return Err(MmioMapError::WouldExposeMsixTable);
    }
    if bar_index == m.pba_bar && overlaps(offset, length, pba_region(m)) {
        return Err(MmioMapError::WouldExposePba);
    }
    Ok(())
}

fn table_region(m: &MsixInfo) -> (u64, u64) {
    let start = m.table_offset as u64;
    let entries = (m.table_size as u64) + 1;
    let bytes = entries * MSIX_ENTRY_SIZE as u64;
    (start, start + bytes)
}

fn pba_region(m: &MsixInfo) -> (u64, u64) {
    let start = m.pba_offset as u64;
    let entries = (m.table_size as u64) + 1;
    let qwords = (entries + 63) / 64;
    let bytes = qwords * 8;
    (start, start + bytes)
}

fn overlaps(offset: u64, length: u64, region: (u64, u64)) -> bool {
    let req_end = offset.saturating_add(length);
    offset < region.1 && region.0 < req_end
}
