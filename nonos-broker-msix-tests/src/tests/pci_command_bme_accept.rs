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
use crate::drivers::pci::constants::{CFG_COMMAND, CMD_BUS_MASTER};

use super::pci_setup::{msix_info, req};

#[test]
fn command_bme_set_accepted() {
    let cur = 0x0006u16;
    let new = cur | CMD_BUS_MASTER;
    let action = validate(&req(CFG_COMMAND as u32, new), Some(&msix_info()), cur).unwrap();
    assert_eq!(action, WriteAction::Command(new));
}

#[test]
fn command_bme_clear_accepted() {
    let cur = 0x0006u16 | CMD_BUS_MASTER;
    let new = cur & !CMD_BUS_MASTER;
    let action = validate(&req(CFG_COMMAND as u32, new), Some(&msix_info()), cur).unwrap();
    assert_eq!(action, WriteAction::Command(new));
}
