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

#[test]
fn test_rx_desc_size() {
    assert_eq!(core::mem::size_of::<E1000RxDesc>(), 16);
}

#[test]
fn test_tx_desc_size() {
    assert_eq!(core::mem::size_of::<E1000TxDesc>(), 16);
}

#[test]
fn test_rx_desc_default() {
    let desc = E1000RxDesc::default();
    assert_eq!(desc.buffer_addr, 0);
    assert_eq!(desc.length, 0);
    assert_eq!(desc.checksum, 0);
    assert_eq!(desc.status, 0);
    assert_eq!(desc.errors, 0);
    assert_eq!(desc.special, 0);
}

#[test]
fn test_tx_desc_default() {
    let desc = E1000TxDesc::default();
    assert_eq!(desc.buffer_addr, 0);
    assert_eq!(desc.length, 0);
    assert_eq!(desc.cso, 0);
    assert_eq!(desc.cmd, 0);
    assert_eq!(desc.status, 0);
    assert_eq!(desc.css, 0);
    assert_eq!(desc.special, 0);
}

#[test]
fn test_rx_desc_status_dd() {
    assert_eq!(E1000RxDesc::STATUS_DD, 0x01);
}

#[test]
fn test_rx_desc_status_eop() {
    assert_eq!(E1000RxDesc::STATUS_EOP, 0x02);
}

#[test]
fn test_rx_desc_status_ixsm() {
    assert_eq!(E1000RxDesc::STATUS_IXSM, 0x04);
}

#[test]
fn test_rx_desc_status_vp() {
    assert_eq!(E1000RxDesc::STATUS_VP, 0x08);
}

#[test]
fn test_rx_desc_status_tcpcs() {
    assert_eq!(E1000RxDesc::STATUS_TCPCS, 0x20);
}

#[test]
fn test_rx_desc_status_ipcs() {
    assert_eq!(E1000RxDesc::STATUS_IPCS, 0x40);
}

#[test]
fn test_rx_desc_is_done_false() {
    let desc = E1000RxDesc::default();
    assert!(!desc.is_done());
}

#[test]
fn test_rx_desc_is_done_true() {
    let mut desc = E1000RxDesc::default();
    desc.status = E1000RxDesc::STATUS_DD;
    assert!(desc.is_done());
}

#[test]
fn test_rx_desc_is_eop_false() {
    let desc = E1000RxDesc::default();
    assert!(!desc.is_eop());
}

#[test]
fn test_rx_desc_is_eop_true() {
    let mut desc = E1000RxDesc::default();
    desc.status = E1000RxDesc::STATUS_EOP;
    assert!(desc.is_eop());
}

#[test]
fn test_rx_desc_has_error_false() {
    let desc = E1000RxDesc::default();
    assert!(!desc.has_error());
}

#[test]
fn test_rx_desc_has_error_true() {
    let mut desc = E1000RxDesc::default();
    desc.errors = 0x01;
    assert!(desc.has_error());
}

#[test]
fn test_rx_desc_is_vlan_false() {
    let desc = E1000RxDesc::default();
    assert!(!desc.is_vlan());
}

#[test]
fn test_rx_desc_is_vlan_true() {
    let mut desc = E1000RxDesc::default();
    desc.status = E1000RxDesc::STATUS_VP;
    assert!(desc.is_vlan());
}

#[test]
fn test_rx_desc_vlan_tag_none() {
    let desc = E1000RxDesc::default();
    assert!(desc.vlan_tag().is_none());
}

#[test]
fn test_rx_desc_vlan_tag_some() {
    let mut desc = E1000RxDesc::default();
    desc.status = E1000RxDesc::STATUS_VP;
    desc.special = 100;
    assert_eq!(desc.vlan_tag(), Some(100));
}

#[test]
fn test_rx_desc_packet_len() {
    let mut desc = E1000RxDesc::default();
    desc.length = 1500;
    assert_eq!(desc.packet_len(), 1500);
}

#[test]
fn test_rx_desc_reset() {
    let mut desc = E1000RxDesc::default();
    desc.status = 0xFF;
    desc.length = 1000;
    desc.errors = 0x0F;
    desc.checksum = 0x1234;
    desc.special = 0x5678;
    desc.reset();
    assert_eq!(desc.status, 0);
    assert_eq!(desc.length, 0);
    assert_eq!(desc.errors, 0);
    assert_eq!(desc.checksum, 0);
    assert_eq!(desc.special, 0);
}

#[test]
fn test_tx_desc_status_dd() {
    assert_eq!(E1000TxDesc::STATUS_DD, 0x01);
}

#[test]
fn test_tx_desc_status_ec() {
    assert_eq!(E1000TxDesc::STATUS_EC, 0x02);
}

#[test]
fn test_tx_desc_status_lc() {
    assert_eq!(E1000TxDesc::STATUS_LC, 0x04);
}

#[test]
fn test_tx_desc_is_done_false() {
    let desc = E1000TxDesc::default();
    assert!(!desc.is_done());
}

#[test]
fn test_tx_desc_is_done_true() {
    let mut desc = E1000TxDesc::default();
    desc.status = E1000TxDesc::STATUS_DD;
    assert!(desc.is_done());
}

#[test]
fn test_tx_desc_had_excess_collisions_false() {
    let desc = E1000TxDesc::default();
    assert!(!desc.had_excess_collisions());
}

#[test]
fn test_tx_desc_had_excess_collisions_true() {
    let mut desc = E1000TxDesc::default();
    desc.status = E1000TxDesc::STATUS_EC;
    assert!(desc.had_excess_collisions());
}

#[test]
fn test_tx_desc_had_late_collision_false() {
    let desc = E1000TxDesc::default();
    assert!(!desc.had_late_collision());
}

#[test]
fn test_tx_desc_had_late_collision_true() {
    let mut desc = E1000TxDesc::default();
    desc.status = E1000TxDesc::STATUS_LC;
    assert!(desc.had_late_collision());
}

#[test]
fn test_tx_desc_has_error_false() {
    let desc = E1000TxDesc::default();
    assert!(!desc.has_error());
}

#[test]
fn test_tx_desc_has_error_true_ec() {
    let mut desc = E1000TxDesc::default();
    desc.status = E1000TxDesc::STATUS_EC;
    assert!(desc.has_error());
}

#[test]
fn test_tx_desc_has_error_true_lc() {
    let mut desc = E1000TxDesc::default();
    desc.status = E1000TxDesc::STATUS_LC;
    assert!(desc.has_error());
}

#[test]
fn test_tx_desc_setup() {
    let mut desc = E1000TxDesc::default();
    desc.setup(0x1000_0000, 1500, 0x0B);
    assert_eq!(desc.buffer_addr, 0x1000_0000);
    assert_eq!(desc.length, 1500);
    assert_eq!(desc.cmd, 0x0B);
    assert_eq!(desc.status, 0);
    assert_eq!(desc.cso, 0);
    assert_eq!(desc.css, 0);
    assert_eq!(desc.special, 0);
}

#[test]
fn test_tx_desc_reset() {
    let mut desc = E1000TxDesc::default();
    desc.setup(0x1000_0000, 1500, 0x0B);
    desc.reset();
    assert_eq!(desc.length, 0);
    assert_eq!(desc.cmd, 0);
    assert_eq!(desc.status, E1000TxDesc::STATUS_DD);
    assert_eq!(desc.cso, 0);
    assert_eq!(desc.css, 0);
    assert_eq!(desc.special, 0);
}

#[test]
fn test_rx_desc_copy() {
    let mut desc1 = E1000RxDesc::default();
    desc1.buffer_addr = 0x1234;
    desc1.length = 500;
    let desc2 = desc1;
    assert_eq!(desc1.buffer_addr, desc2.buffer_addr);
    assert_eq!(desc1.length, desc2.length);
}

#[test]
fn test_tx_desc_copy() {
    let mut desc1 = E1000TxDesc::default();
    desc1.buffer_addr = 0x5678;
    desc1.length = 1000;
    let desc2 = desc1;
    assert_eq!(desc1.buffer_addr, desc2.buffer_addr);
    assert_eq!(desc1.length, desc2.length);
}

#[test]
fn test_rx_desc_done_and_eop() {
    let mut desc = E1000RxDesc::default();
    desc.status = E1000RxDesc::STATUS_DD | E1000RxDesc::STATUS_EOP;
    assert!(desc.is_done());
    assert!(desc.is_eop());
}

#[test]
fn test_tx_desc_done_but_error() {
    let mut desc = E1000TxDesc::default();
    desc.status = E1000TxDesc::STATUS_DD | E1000TxDesc::STATUS_EC;
    assert!(desc.is_done());
    assert!(desc.has_error());
}
