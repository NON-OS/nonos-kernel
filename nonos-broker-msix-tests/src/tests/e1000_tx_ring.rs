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

//! Drive `TxRing::post` against a host-allocated descriptor ring.
//! Each post returns the index it used; the descriptor must carry
//! the EOP|IFCS|RS command and zero status so the device knows it
//! owns the slot.

use crate::constants::queue::{
    TX_BUFFER_LEN, TX_CMD_EOP, TX_CMD_IFCS, TX_CMD_RS, TX_DESC_COUNT, TX_STATUS_DD,
};
use crate::queue::layout::TxDesc;
use crate::queue::tx::TxRing;

fn fresh_ring() -> (alloc::vec::Vec<TxDesc>, TxRing) {
    let descs = alloc::vec![TxDesc::default(); TX_DESC_COUNT];
    let user_va = descs.as_ptr() as u64;
    (descs, TxRing::new(user_va, 0xD000_0000, 0xD000_0000))
}

#[test]
fn post_returns_zero_first() {
    let (_descs, mut tx) = fresh_ring();
    assert_eq!(tx.post(64), 0);
    assert_eq!(tx.tail, 1);
}

#[test]
fn post_writes_cmd_and_clears_status() {
    let (descs, mut tx) = fresh_ring();
    let idx = tx.post(128);
    let d = descs[idx as usize];
    assert_eq!(d.cmd, TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS);
    assert_eq!(d.length, 128);
    assert_eq!(d.status, 0);
}

#[test]
fn done_flips_when_device_sets_dd() {
    let (mut descs, mut tx) = fresh_ring();
    let idx = tx.post(60);
    assert!(!tx.done(idx));
    descs[idx as usize].status = TX_STATUS_DD;
    assert!(tx.done(idx));
}

#[test]
fn tail_wraps_at_ring_boundary() {
    let (_descs, mut tx) = fresh_ring();
    tx.tail = (TX_DESC_COUNT - 1) as u16;
    let idx = tx.post(64);
    assert_eq!(idx, (TX_DESC_COUNT - 1) as u16);
    assert_eq!(tx.tail, 0, "tail wraps");
}

#[test]
fn buffer_phys_strides_by_buffer_len() {
    let (_descs, tx) = fresh_ring();
    let phys0 = tx.buffer_phys(0);
    let phys1 = tx.buffer_phys(1);
    assert_eq!(phys1 - phys0, TX_BUFFER_LEN as u64);
}
