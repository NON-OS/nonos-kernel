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

use crate::broker::pci::allowlist::validate;
use crate::broker::pci::types::WriteAction;
use crate::drivers::pci::constants::MSIX_CTRL_FUNCTION_MASK;

use super::pci_setup::{msix_info, req, MSIX_CTRL_OFFSET};

#[test]
fn msix_function_mask_set_accepted() {
    let cur = 0x0007u16;
    let new = cur | MSIX_CTRL_FUNCTION_MASK;
    let action = validate(&req(MSIX_CTRL_OFFSET, new), Some(&msix_info()), cur).unwrap();
    assert_eq!(action, WriteAction::MsixControl { offset: MSIX_CTRL_OFFSET as u16, value: new });
}

#[test]
fn msix_function_mask_clear_accepted() {
    let cur = 0x0007u16 | MSIX_CTRL_FUNCTION_MASK;
    let new = cur & !MSIX_CTRL_FUNCTION_MASK;
    let action = validate(&req(MSIX_CTRL_OFFSET, new), Some(&msix_info()), cur).unwrap();
    assert_eq!(action, WriteAction::MsixControl { offset: MSIX_CTRL_OFFSET as u16, value: new });
}
