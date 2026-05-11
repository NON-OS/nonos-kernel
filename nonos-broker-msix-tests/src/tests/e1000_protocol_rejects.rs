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

//! The decoder must reject anything whose magic or version does
//! not match — virtio_net's "NNET" magic must NOT decode as a
//! valid e1000 frame, and a v0 / v2 envelope must surface as
//! `None` so the server replies `EINVAL`.

use crate::protocol::decode::decode_request;
use crate::protocol::header::{HDR_LEN, MAGIC, VERSION};

const VIRTIO_NET_MAGIC: u32 = 0x4E4E_4554; // "NNET"

#[test]
fn wrong_magic_rejected() {
    let mut buf = [0u8; HDR_LEN];
    buf[0..4].copy_from_slice(&VIRTIO_NET_MAGIC.to_le_bytes());
    buf[4..6].copy_from_slice(&VERSION.to_le_bytes());
    assert!(decode_request(&buf).is_none());
}

#[test]
fn wrong_version_rejected() {
    let mut buf = [0u8; HDR_LEN];
    buf[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    buf[4..6].copy_from_slice(&(VERSION + 1).to_le_bytes());
    assert!(decode_request(&buf).is_none());
}

#[test]
fn short_envelope_rejected() {
    let buf = [0u8; HDR_LEN - 1];
    assert!(decode_request(&buf).is_none());
}
