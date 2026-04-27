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

use crate::drivers::xhci::constants;
use crate::test::framework::TestResult;

pub(crate) fn test_portsc_change_bits() -> TestResult {
    let change_bits = constants::PORTSC_CHANGE_BITS;
    if change_bits & constants::PORTSC_CSC != constants::PORTSC_CSC {
        return TestResult::Fail;
    }
    if change_bits & constants::PORTSC_PEC != constants::PORTSC_PEC {
        return TestResult::Fail;
    }
    if change_bits & constants::PORTSC_PRC != constants::PORTSC_PRC {
        return TestResult::Fail;
    }
    if change_bits & constants::PORTSC_PED != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_trb_alignment_constant() -> TestResult {
    if constants::TRB_ALIGNMENT != 16 {
        return TestResult::Fail;
    }
    if constants::DMA_MIN_ALIGNMENT < constants::TRB_ALIGNMENT as usize {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ring_size_constants() -> TestResult {
    if constants::MIN_RING_SIZE < 16 {
        return TestResult::Fail;
    }
    if constants::MAX_RING_SIZE < constants::MIN_RING_SIZE {
        return TestResult::Fail;
    }
    if constants::DEFAULT_CMD_RING_SIZE < constants::MIN_RING_SIZE {
        return TestResult::Fail;
    }
    if constants::DEFAULT_EVENT_RING_SIZE < constants::MIN_RING_SIZE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_valid_trb_types_lists() -> TestResult {
    if !constants::VALID_TRANSFER_TRB_TYPES.contains(&constants::TRB_TYPE_NORMAL) {
        return TestResult::Fail;
    }
    if !constants::VALID_TRANSFER_TRB_TYPES.contains(&constants::TRB_TYPE_SETUP_STAGE) {
        return TestResult::Fail;
    }
    if !constants::VALID_TRANSFER_TRB_TYPES.contains(&constants::TRB_TYPE_LINK) {
        return TestResult::Fail;
    }
    if !constants::VALID_COMMAND_TRB_TYPES.contains(&constants::TRB_TYPE_ENABLE_SLOT_CMD) {
        return TestResult::Fail;
    }
    if !constants::VALID_COMMAND_TRB_TYPES.contains(&constants::TRB_TYPE_ADDRESS_DEVICE_CMD) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
