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

use crate::drivers::xhci::types;
use crate::test::framework::TestResult;
use core::mem;

pub(crate) fn test_slot_context_size() -> TestResult {
    if mem::size_of::<types::SlotContext>() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ep_context_size() -> TestResult {
    if mem::size_of::<types::EpContext>() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_context_alignment() -> TestResult {
    if mem::align_of::<types::DeviceContext>() != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_slot_context_fields() -> TestResult {
    let mut slot = types::SlotContext::default();

    slot.set_speed(4);
    if slot.speed() != 4 {
        return TestResult::Fail;
    }

    slot.set_root_hub_port(3);
    if slot.root_hub_port() != 3 {
        return TestResult::Fail;
    }

    slot.set_context_entries(5);
    if slot.context_entries() != 5 {
        return TestResult::Fail;
    }

    slot.set_hub(true);
    if !slot.hub() {
        return TestResult::Fail;
    }

    slot.set_mtt(true);
    if !slot.mtt() {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_ep_context_dequeue_pointer() -> TestResult {
    let mut ep = types::EpContext::default();

    ep.set_tr_dequeue_pointer(0x1000_0010, true);
    if ep.tr_dequeue_pointer() != 0x1000_0010 {
        return TestResult::Fail;
    }
    if !ep.dcs() {
        return TestResult::Fail;
    }

    ep.set_tr_dequeue_pointer(0x2000_0020, false);
    if ep.tr_dequeue_pointer() != 0x2000_0020 {
        return TestResult::Fail;
    }
    if ep.dcs() {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_ep_context_max_packet_size() -> TestResult {
    let mut ep = types::EpContext::default();

    ep.set_max_packet_size(512);
    if ep.max_packet_size() != 512 {
        return TestResult::Fail;
    }

    ep.set_max_packet_size(1024);
    if ep.max_packet_size() != 1024 {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_ep_addr_to_dci() -> TestResult {
    if types::DeviceContext::ep_addr_to_dci(0x00) != 1 {
        return TestResult::Fail;
    }
    if types::DeviceContext::ep_addr_to_dci(0x80) != 1 {
        return TestResult::Fail;
    }
    if types::DeviceContext::ep_addr_to_dci(0x01) != 2 {
        return TestResult::Fail;
    }
    if types::DeviceContext::ep_addr_to_dci(0x81) != 3 {
        return TestResult::Fail;
    }
    if types::DeviceContext::ep_addr_to_dci(0x02) != 4 {
        return TestResult::Fail;
    }
    if types::DeviceContext::ep_addr_to_dci(0x82) != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_input_control_context() -> TestResult {
    let mut icc = types::InputControlContext::default();

    icc.add_context(0);
    icc.add_context(1);
    if !icc.is_adding(0) {
        return TestResult::Fail;
    }
    if !icc.is_adding(1) {
        return TestResult::Fail;
    }
    if icc.is_adding(2) {
        return TestResult::Fail;
    }

    icc.drop_context(3);
    if !icc.is_dropping(3) {
        return TestResult::Fail;
    }
    if icc.is_dropping(0) {
        return TestResult::Fail;
    }

    TestResult::Pass
}
