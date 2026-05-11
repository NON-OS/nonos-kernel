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

//! Documented behaviour: writing the current Command value back is
//! accepted as a no-op `WriteAction::Command`. Rejecting it would
//! force every capsule to read-modify-write through a careful diff;
//! accepting it lets the kernel round-trip the value safely because
//! the bit-change check is XOR against the current register, so
//! `(new ^ current) & !CMD_BUS_MASTER` is zero by construction.

use crate::broker::pci::allowlist::validate;
use crate::broker::pci::types::WriteAction;
use crate::drivers::pci::constants::CFG_COMMAND;

use super::pci_setup::{msix_info, req};

#[test]
fn command_same_value_is_accepted_no_op() {
    let cur = 0x0146u16;
    let action = validate(&req(CFG_COMMAND as u32, cur), Some(&msix_info()), cur).unwrap();
    assert_eq!(action, WriteAction::Command(cur));
}
