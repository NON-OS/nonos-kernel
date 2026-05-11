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

//! The MSI-X Message Control register's low 11 bits are the table
//! size — a read-only field the device populates. Bits 11..13 are
//! reserved. Writing any of those must be rejected; only Function
//! Mask (bit 14) and Enable (bit 15) belong to the capsule.

use crate::broker::pci::allowlist::validate;
use crate::broker::pci::types::PciWriteError;

use super::pci_setup::{msix_info, req, MSIX_CTRL_OFFSET};

fn assert_rejected(cur: u16, new: u16) {
    let err = validate(&req(MSIX_CTRL_OFFSET, new), Some(&msix_info()), cur).unwrap_err();
    assert_eq!(err, PciWriteError::BitsNotAllowed);
}

#[test]
fn msix_rejects_table_size_field_flip() {
    assert_rejected(0x0007, 0x0008);
}

#[test]
fn msix_rejects_reserved_bit_flip() {
    assert_rejected(0, 1 << 12);
}

#[test]
fn msix_rejects_low_bit_flip() {
    assert_rejected(0, 1);
}
