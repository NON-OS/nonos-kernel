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

//! Wire-form size + alignment of the e1000 RX/TX descriptors.
//! The 8254x manual fixes both at exactly 16 bytes; a stray
//! padding byte from a Rust struct reorder would silently drift
//! the head/tail arithmetic in `RxRing::descriptor` /
//! `TxRing::descriptor`. The const-asserts inside `layout.rs`
//! also catch this at build time, but the host test makes the
//! invariant visible in the test report.

use core::mem::{align_of, size_of};

use crate::constants::queue::DESC_BYTES;
use crate::queue::layout::{RxDesc, TxDesc};

#[test]
fn rx_desc_is_16_bytes() {
    assert_eq!(size_of::<RxDesc>(), 16);
    assert_eq!(size_of::<RxDesc>(), DESC_BYTES);
}

#[test]
fn tx_desc_is_16_bytes() {
    assert_eq!(size_of::<TxDesc>(), 16);
    assert_eq!(size_of::<TxDesc>(), DESC_BYTES);
}

#[test]
fn descriptors_have_8_byte_alignment_for_buffer_addr() {
    assert!(align_of::<RxDesc>() >= 8);
    assert!(align_of::<TxDesc>() >= 8);
}
