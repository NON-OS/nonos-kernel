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

//! Every Command bit other than Bus Master Enable must be rejected.
//! The cases here cover IO Space (bit 0), Memory Space (bit 1),
//! Special Cycles (bit 3), Interrupt Disable (bit 10), and the
//! Reserved bits via a high-bit set, so a forgotten mask in the
//! validator would surface as a failing case rather than a silent
//! pass.

use crate::broker::pci::allowlist::validate;
use crate::broker::pci::types::PciWriteError;
use crate::drivers::pci::constants::CFG_COMMAND;

use super::pci_setup::{msix_info, req};

fn assert_rejected(cur: u16, new: u16) {
    let err = validate(&req(CFG_COMMAND as u32, new), Some(&msix_info()), cur).unwrap_err();
    assert_eq!(err, PciWriteError::BitsNotAllowed);
}

#[test]
fn command_rejects_io_space_flip() {
    assert_rejected(0b0000_0000_0000_0000, 0b0000_0000_0000_0001);
}

#[test]
fn command_rejects_memory_space_flip() {
    assert_rejected(0b0000_0000_0000_0010, 0b0000_0000_0000_0000);
}

#[test]
fn command_rejects_special_cycles_flip() {
    assert_rejected(0, 1 << 3);
}

#[test]
fn command_rejects_interrupt_disable_flip() {
    assert_rejected(0, 1 << 10);
}

#[test]
fn command_rejects_high_reserved_flip() {
    assert_rejected(0, 1 << 11);
}
