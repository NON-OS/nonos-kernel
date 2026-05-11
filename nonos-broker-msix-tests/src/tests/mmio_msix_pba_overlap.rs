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

//! The pending-bit array is read-only by hardware contract, but
//! exposing it would still let a capsule observe per-vector pending
//! state outside the broker's notification path. Treat it the same
//! way as the table itself.

use crate::broker::mmio::msix_exclusion::validate;
use crate::broker::mmio::types::MmioMapError;

use super::pci_setup::msix_info;

#[test]
fn map_covering_pba_region_rejects() {
    // 8 vectors → ceil(8/64) = 1 qword = 8 bytes at pba_offset.
    let m = msix_info();
    let err = validate(Some(&m), m.pba_bar, m.pba_offset as u64, 0x1000).unwrap_err();
    assert_eq!(err, MmioMapError::WouldExposePba);
}

#[test]
fn map_just_above_pba_allowed() {
    let m = msix_info();
    validate(Some(&m), m.pba_bar, (m.pba_offset as u64) + 8, 0x1000)
        .expect("starts at end of pba");
}
