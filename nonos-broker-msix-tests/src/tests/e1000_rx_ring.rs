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

//! Drive `RxRing::consume` against a host-allocated descriptor
//! ring. With no `DD` bit set the consumer reports empty; once
//! the device-side flag flips, consume returns the index + length
//! and clears DD so the slot can be re-armed by the next pass.

use crate::constants::queue::{RX_DESC_COUNT, RX_STATUS_DD};
use crate::queue::layout::RxDesc;
use crate::queue::rx::RxRing;

fn fresh_ring() -> (alloc::vec::Vec<RxDesc>, RxRing) {
    let descs = alloc::vec![RxDesc::default(); RX_DESC_COUNT];
    let user_va = descs.as_ptr() as u64;
    (descs, RxRing::new(user_va, 0xC000_0000, 0xC000_0000))
}

#[test]
fn empty_ring_returns_none() {
    let (_descs, mut rx) = fresh_ring();
    assert!(rx.consume().is_none());
}

#[test]
fn single_frame_consumes_and_clears_dd() {
    let (mut descs, mut rx) = fresh_ring();
    descs[0].status = RX_STATUS_DD;
    descs[0].length = 64;
    let (idx, len) = rx.consume().expect("DD set, consumer should return");
    assert_eq!(idx, 0);
    assert_eq!(len, 64);
    assert_eq!(descs[0].status & RX_STATUS_DD, 0, "DD should be cleared after consume");
    assert_eq!(rx.head, 1);
}

#[test]
fn head_wraps_at_ring_boundary() {
    let (mut descs, mut rx) = fresh_ring();
    let last = RX_DESC_COUNT - 1;
    descs[last].status = RX_STATUS_DD;
    rx.head = last as u16;
    let _ = rx.consume().expect("last slot ready");
    assert_eq!(rx.head, 0, "head wraps from last back to 0");
}
