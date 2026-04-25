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

use crate::drivers::e1000::descriptors::{E1000RxDesc, E1000TxDesc};
use crate::test::framework::TestResult;

pub(crate) fn test_rx_desc_size() -> TestResult {
    if core::mem::size_of::<E1000RxDesc>() != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_desc_size() -> TestResult {
    if core::mem::size_of::<E1000TxDesc>() != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_default() -> TestResult {
    let desc = E1000RxDesc::default();
    if desc.buffer_addr != 0 {
        return TestResult::Fail;
    }
    if desc.length != 0 {
        return TestResult::Fail;
    }
    if desc.checksum != 0 {
        return TestResult::Fail;
    }
    if desc.status != 0 {
        return TestResult::Fail;
    }
    if desc.errors != 0 {
        return TestResult::Fail;
    }
    if desc.special != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_desc_default() -> TestResult {
    let desc = E1000TxDesc::default();
    if desc.buffer_addr != 0 {
        return TestResult::Fail;
    }
    if desc.length != 0 {
        return TestResult::Fail;
    }
    if desc.cso != 0 {
        return TestResult::Fail;
    }
    if desc.cmd != 0 {
        return TestResult::Fail;
    }
    if desc.status != 0 {
        return TestResult::Fail;
    }
    if desc.css != 0 {
        return TestResult::Fail;
    }
    if desc.special != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_status_dd() -> TestResult {
    if E1000RxDesc::STATUS_DD != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_status_eop() -> TestResult {
    if E1000RxDesc::STATUS_EOP != 0x02 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_status_ixsm() -> TestResult {
    if E1000RxDesc::STATUS_IXSM != 0x04 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_status_vp() -> TestResult {
    if E1000RxDesc::STATUS_VP != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_status_tcpcs() -> TestResult {
    if E1000RxDesc::STATUS_TCPCS != 0x20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_status_ipcs() -> TestResult {
    if E1000RxDesc::STATUS_IPCS != 0x40 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_is_done_false() -> TestResult {
    let desc = E1000RxDesc::default();
    if desc.is_done() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_is_done_true() -> TestResult {
    let mut desc = E1000RxDesc::default();
    desc.status = E1000RxDesc::STATUS_DD;
    if !desc.is_done() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_is_eop_false() -> TestResult {
    let desc = E1000RxDesc::default();
    if desc.is_eop() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_is_eop_true() -> TestResult {
    let mut desc = E1000RxDesc::default();
    desc.status = E1000RxDesc::STATUS_EOP;
    if !desc.is_eop() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_has_error_false() -> TestResult {
    let desc = E1000RxDesc::default();
    if desc.has_error() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_has_error_true() -> TestResult {
    let mut desc = E1000RxDesc::default();
    desc.errors = 0x01;
    if !desc.has_error() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_is_vlan_false() -> TestResult {
    let desc = E1000RxDesc::default();
    if desc.is_vlan() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_is_vlan_true() -> TestResult {
    let mut desc = E1000RxDesc::default();
    desc.status = E1000RxDesc::STATUS_VP;
    if !desc.is_vlan() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_vlan_tag_none() -> TestResult {
    let desc = E1000RxDesc::default();
    if desc.vlan_tag().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_vlan_tag_some() -> TestResult {
    let mut desc = E1000RxDesc::default();
    desc.status = E1000RxDesc::STATUS_VP;
    desc.special = 100;
    if desc.vlan_tag() != Some(100) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_packet_len() -> TestResult {
    let mut desc = E1000RxDesc::default();
    desc.length = 1500;
    if desc.packet_len() != 1500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_reset() -> TestResult {
    let mut desc = E1000RxDesc::default();
    desc.status = 0xFF;
    desc.length = 1000;
    desc.errors = 0x0F;
    desc.checksum = 0x1234;
    desc.special = 0x5678;
    desc.reset();
    if desc.status != 0 {
        return TestResult::Fail;
    }
    if desc.length != 0 {
        return TestResult::Fail;
    }
    if desc.errors != 0 {
        return TestResult::Fail;
    }
    if desc.checksum != 0 {
        return TestResult::Fail;
    }
    if desc.special != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_desc_status_dd() -> TestResult {
    if E1000TxDesc::STATUS_DD != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_desc_status_ec() -> TestResult {
    if E1000TxDesc::STATUS_EC != 0x02 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_desc_status_lc() -> TestResult {
    if E1000TxDesc::STATUS_LC != 0x04 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_desc_is_done_false() -> TestResult {
    let desc = E1000TxDesc::default();
    if desc.is_done() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_desc_is_done_true() -> TestResult {
    let mut desc = E1000TxDesc::default();
    desc.status = E1000TxDesc::STATUS_DD;
    if !desc.is_done() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_desc_had_excess_collisions_false() -> TestResult {
    let desc = E1000TxDesc::default();
    if desc.had_excess_collisions() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_desc_had_excess_collisions_true() -> TestResult {
    let mut desc = E1000TxDesc::default();
    desc.status = E1000TxDesc::STATUS_EC;
    if !desc.had_excess_collisions() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_desc_had_late_collision_false() -> TestResult {
    let desc = E1000TxDesc::default();
    if desc.had_late_collision() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_desc_had_late_collision_true() -> TestResult {
    let mut desc = E1000TxDesc::default();
    desc.status = E1000TxDesc::STATUS_LC;
    if !desc.had_late_collision() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_desc_has_error_false() -> TestResult {
    let desc = E1000TxDesc::default();
    if desc.has_error() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_desc_has_error_true_ec() -> TestResult {
    let mut desc = E1000TxDesc::default();
    desc.status = E1000TxDesc::STATUS_EC;
    if !desc.has_error() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_desc_has_error_true_lc() -> TestResult {
    let mut desc = E1000TxDesc::default();
    desc.status = E1000TxDesc::STATUS_LC;
    if !desc.has_error() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_desc_setup() -> TestResult {
    let mut desc = E1000TxDesc::default();
    desc.setup(0x1000_0000, 1500, 0x0B);
    if desc.buffer_addr != 0x1000_0000 {
        return TestResult::Fail;
    }
    if desc.length != 1500 {
        return TestResult::Fail;
    }
    if desc.cmd != 0x0B {
        return TestResult::Fail;
    }
    if desc.status != 0 {
        return TestResult::Fail;
    }
    if desc.cso != 0 {
        return TestResult::Fail;
    }
    if desc.css != 0 {
        return TestResult::Fail;
    }
    if desc.special != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_desc_reset() -> TestResult {
    let mut desc = E1000TxDesc::default();
    desc.setup(0x1000_0000, 1500, 0x0B);
    desc.reset();
    if desc.length != 0 {
        return TestResult::Fail;
    }
    if desc.cmd != 0 {
        return TestResult::Fail;
    }
    if desc.status != E1000TxDesc::STATUS_DD {
        return TestResult::Fail;
    }
    if desc.cso != 0 {
        return TestResult::Fail;
    }
    if desc.css != 0 {
        return TestResult::Fail;
    }
    if desc.special != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_copy() -> TestResult {
    let mut desc1 = E1000RxDesc::default();
    desc1.buffer_addr = 0x1234;
    desc1.length = 500;
    let desc2 = desc1;
    if desc1.buffer_addr != desc2.buffer_addr {
        return TestResult::Fail;
    }
    if desc1.length != desc2.length {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_desc_copy() -> TestResult {
    let mut desc1 = E1000TxDesc::default();
    desc1.buffer_addr = 0x5678;
    desc1.length = 1000;
    let desc2 = desc1;
    if desc1.buffer_addr != desc2.buffer_addr {
        return TestResult::Fail;
    }
    if desc1.length != desc2.length {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_rx_desc_done_and_eop() -> TestResult {
    let mut desc = E1000RxDesc::default();
    desc.status = E1000RxDesc::STATUS_DD | E1000RxDesc::STATUS_EOP;
    if !desc.is_done() {
        return TestResult::Fail;
    }
    if !desc.is_eop() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tx_desc_done_but_error() -> TestResult {
    let mut desc = E1000TxDesc::default();
    desc.status = E1000TxDesc::STATUS_DD | E1000TxDesc::STATUS_EC;
    if !desc.is_done() {
        return TestResult::Fail;
    }
    if !desc.has_error() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
