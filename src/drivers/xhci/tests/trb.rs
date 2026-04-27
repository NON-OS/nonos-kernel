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

use crate::drivers::xhci::{constants, trb, Trb};
use crate::test::framework::TestResult;
use core::mem;

pub(crate) fn test_trb_size_and_alignment() -> TestResult {
    if mem::size_of::<Trb>() != 16 {
        return TestResult::Fail;
    }
    if mem::align_of::<Trb>() != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trb_type_field() -> TestResult {
    let mut trb = Trb::default();

    trb.set_type(constants::TRB_TYPE_NORMAL);
    if trb.get_type() != constants::TRB_TYPE_NORMAL {
        return TestResult::Fail;
    }

    trb.set_type(constants::TRB_TYPE_LINK);
    if trb.get_type() != constants::TRB_TYPE_LINK {
        return TestResult::Fail;
    }

    trb.set_type(constants::TRB_TYPE_SETUP_STAGE);
    if trb.get_type() != constants::TRB_TYPE_SETUP_STAGE {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_trb_cycle_bit() -> TestResult {
    let mut trb = Trb::default();

    if trb.get_cycle() {
        return TestResult::Fail;
    }

    trb.set_cycle(true);
    if !trb.get_cycle() {
        return TestResult::Fail;
    }

    trb.set_cycle(false);
    if trb.get_cycle() {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_trb_pointer() -> TestResult {
    let mut trb = Trb::default();
    let ptr = 0x1234_5678_9ABC_DEF0u64;

    trb.set_pointer(ptr);
    if trb.get_pointer() != ptr {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_trb_ioc_bit() -> TestResult {
    let mut trb = Trb::default();

    if trb.ioc() {
        return TestResult::Fail;
    }

    trb.set_ioc(true);
    if !trb.ioc() {
        return TestResult::Fail;
    }

    trb.set_ioc(false);
    if trb.ioc() {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_trb_pointer_alignment_validation() -> TestResult {
    if Trb::validate_pointer_alignment(0x1000).is_err() {
        return TestResult::Fail;
    }
    if Trb::validate_pointer_alignment(0x1010).is_err() {
        return TestResult::Fail;
    }
    if Trb::validate_pointer_alignment(0x1001).is_ok() {
        return TestResult::Fail;
    }
    if Trb::validate_pointer_alignment(0x1008).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_setup_stage_builder() -> TestResult {
    let trb = trb::SetupStageTrbBuilder::new()
        .setup_packet(0x80, 0x06, 0x0100, 0x0000, 18)
        .transfer_type(true, true)
        .cycle(true)
        .build();

    if trb.get_type() != constants::TRB_TYPE_SETUP_STAGE {
        return TestResult::Fail;
    }
    if !trb.get_cycle() {
        return TestResult::Fail;
    }
    if trb.d0 & 0xFF != 0x80 {
        return TestResult::Fail;
    }
    if (trb.d0 >> 8) & 0xFF != 0x06 {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_data_stage_builder() -> TestResult {
    let trb = trb::DataStageTrbBuilder::new()
        .data_buffer(0x1000, 512)
        .direction_in(true)
        .ioc(true)
        .cycle(true)
        .build();

    if trb.get_type() != constants::TRB_TYPE_DATA_STAGE {
        return TestResult::Fail;
    }
    if !trb.get_cycle() {
        return TestResult::Fail;
    }
    if !trb.ioc() {
        return TestResult::Fail;
    }
    if trb.get_pointer() != 0x1000 {
        return TestResult::Fail;
    }
    if trb.get_transfer_length() != 512 {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_status_stage_builder() -> TestResult {
    let trb = trb::StatusStageTrbBuilder::new().direction_in(false).cycle(true).build();

    if trb.get_type() != constants::TRB_TYPE_STATUS_STAGE {
        return TestResult::Fail;
    }
    if !trb.get_cycle() {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_link_trb_builder() -> TestResult {
    let trb = trb::LinkTrbBuilder::new().target(0x2000).toggle_cycle(true).cycle(true).build();

    if trb.get_type() != constants::TRB_TYPE_LINK {
        return TestResult::Fail;
    }
    if !trb.get_cycle() {
        return TestResult::Fail;
    }
    if trb.get_pointer() != 0x2000 {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_enable_slot_command() -> TestResult {
    let trb = trb::enable_slot_command(true);
    if trb.get_type() != constants::TRB_TYPE_ENABLE_SLOT_CMD {
        return TestResult::Fail;
    }
    if !trb.get_cycle() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_address_device_command() -> TestResult {
    let trb = trb::address_device_command(0x3000, 5, false, true);
    if trb.get_type() != constants::TRB_TYPE_ADDRESS_DEVICE_CMD {
        return TestResult::Fail;
    }
    if !trb.get_cycle() {
        return TestResult::Fail;
    }
    if trb.get_pointer() != 0x3000 {
        return TestResult::Fail;
    }
    if trb.slot_id() != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
