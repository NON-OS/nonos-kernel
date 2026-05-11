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

//! Bringing MSI-X up usually flips both Enable and Function Mask
//! in the same write — first set both to come up masked, then a
//! second write clears Function Mask. The validator must accept the
//! combined toggle, not just one bit at a time.

use crate::broker::pci::allowlist::validate;
use crate::broker::pci::types::WriteAction;
use crate::drivers::pci::constants::{MSIX_CTRL_ENABLE, MSIX_CTRL_FUNCTION_MASK};

use super::pci_setup::{msix_info, req, MSIX_CTRL_OFFSET};

#[test]
fn msix_enable_and_function_mask_together_accepted() {
    let cur = 0x0007u16;
    let new = cur | MSIX_CTRL_ENABLE | MSIX_CTRL_FUNCTION_MASK;
    let action = validate(&req(MSIX_CTRL_OFFSET, new), Some(&msix_info()), cur).unwrap();
    assert_eq!(action, WriteAction::MsixControl { offset: MSIX_CTRL_OFFSET as u16, value: new });
}
