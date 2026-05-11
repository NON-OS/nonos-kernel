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

//! Mapping the BAR slice that contains the MSI-X table must be
//! refused — otherwise a capsule with `Mmio` could rewrite the
//! per-vector message and target a different LAPIC.

use crate::broker::mmio::msix_exclusion::validate;
use crate::broker::mmio::types::MmioMapError;

use super::pci_setup::msix_info;

#[test]
fn map_covering_table_region_rejects() {
    // table_offset = 0x1000, table_size = 7 (8 entries), 16 bytes each
    // → table region [0x1000, 0x1080).
    let m = msix_info();
    let err = validate(Some(&m), m.table_bar, 0x1000, 0x1000).unwrap_err();
    assert_eq!(err, MmioMapError::WouldExposeMsixTable);
}

#[test]
fn map_starting_inside_table_rejects() {
    let m = msix_info();
    let err = validate(Some(&m), m.table_bar, 0x1040, 0x40).unwrap_err();
    assert_eq!(err, MmioMapError::WouldExposeMsixTable);
}

#[test]
fn map_just_below_table_allowed() {
    let m = msix_info();
    validate(Some(&m), m.table_bar, 0x0000, 0x1000).expect("ends at table_offset");
}
