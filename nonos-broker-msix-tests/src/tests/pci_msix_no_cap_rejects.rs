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

//! Without an MSI-X capability, the validator must not invent a
//! "would-be" Message Control offset. Any offset other than
//! `CFG_COMMAND` falls through to `OffsetNotAllowed`.

use crate::broker::pci::allowlist::validate;
use crate::broker::pci::types::PciWriteError;

use super::pci_setup::{req, MSIX_CTRL_OFFSET};

#[test]
fn no_msix_cap_rejects_msix_offset_write() {
    let err = validate(&req(MSIX_CTRL_OFFSET, 0), None, 0).unwrap_err();
    assert_eq!(err, PciWriteError::OffsetNotAllowed);
}
