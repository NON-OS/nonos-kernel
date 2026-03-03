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

use super::*;
use core::mem;

#[test]
fn test_trb_size() {
    assert_eq!(mem::size_of::<Trb>(), 16);
}

#[test]
fn test_trb_alignment() {
    assert_eq!(mem::align_of::<Trb>(), 16);
}

#[test]
fn test_trb_type() {
    use super::super::constants::*;

    let mut trb = Trb::new();
    trb.set_type(TRB_TYPE_NORMAL);
    assert_eq!(trb.get_type(), TRB_TYPE_NORMAL);

    trb.set_type(TRB_TYPE_LINK);
    assert_eq!(trb.get_type(), TRB_TYPE_LINK);
}

#[test]
fn test_trb_cycle() {
    let mut trb = Trb::new();
    assert!(!trb.get_cycle());

    trb.set_cycle(true);
    assert!(trb.get_cycle());

    trb.set_cycle(false);
    assert!(!trb.get_cycle());
}

#[test]
fn test_trb_pointer() {
    let mut trb = Trb::new();
    let ptr = 0x1234_5678_9ABC_DEF0u64;
    trb.set_pointer(ptr);
    assert_eq!(trb.get_pointer(), ptr);
}

#[test]
fn test_setup_stage_builder() {
    use super::super::constants::*;

    let trb = SetupStageTrbBuilder::new()
        .setup_packet(0x80, 0x06, 0x0100, 0x0000, 18)
        .transfer_type(true, true)
        .cycle(true)
        .build();

    assert_eq!(trb.get_type(), TRB_TYPE_SETUP_STAGE);
    assert!(trb.get_cycle());
}

#[test]
fn test_enable_slot_command() {
    use super::super::constants::*;

    let trb = enable_slot_command(true);
    assert_eq!(trb.get_type(), TRB_TYPE_ENABLE_SLOT_CMD);
    assert!(trb.get_cycle());
}

#[test]
fn test_pointer_alignment_validation() {
    assert!(Trb::validate_pointer_alignment(0x1000).is_ok());
    assert!(Trb::validate_pointer_alignment(0x1010).is_ok());
    assert!(Trb::validate_pointer_alignment(0x1001).is_err());
}
