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

//! The MSI-X capability layout puts Message Control at `cap + 2`.
//! `cap + 0` is the capability id + next-pointer pair (read-only by
//! contract); `cap + 4` and `cap + 8` are the table/PBA offsets,
//! also read-only. None of these are in the allowlist.

use crate::broker::pci::allowlist::validate;
use crate::broker::pci::types::PciWriteError;

use super::pci_setup::{msix_info, req, MSIX_CAP_OFFSET};

#[test]
fn msix_cap_header_offset_rejects() {
    let err = validate(&req(MSIX_CAP_OFFSET as u32, 0), Some(&msix_info()), 0).unwrap_err();
    assert_eq!(err, PciWriteError::OffsetNotAllowed);
}

#[test]
fn msix_table_offset_rejects() {
    let off = MSIX_CAP_OFFSET as u32 + 4;
    let err = validate(&req(off, 0), Some(&msix_info()), 0).unwrap_err();
    assert_eq!(err, PciWriteError::OffsetNotAllowed);
}

#[test]
fn msix_pba_offset_rejects() {
    let off = MSIX_CAP_OFFSET as u32 + 8;
    let err = validate(&req(off, 0), Some(&msix_info()), 0).unwrap_err();
    assert_eq!(err, PciWriteError::OffsetNotAllowed);
}
