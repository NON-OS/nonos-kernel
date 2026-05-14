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

use nonos_libc::mk_ipc_send;

use crate::controller::{layout, ControllerInfo};
use crate::protocol::{
    encode_response_header, write_status, Request, KERNEL_REPLY_ENDPOINT, RESP_HDR_LEN,
    STREAM_ENTRY_BYTES, STREAM_LAYOUT_HEADER_BYTES,
};
use crate::setup::Driver;

pub fn handle(driver: &Driver, req: &Request, tx: &mut [u8]) {
    let info = ControllerInfo::read(driver.regs);
    let (streams, count) = layout(info);
    let body = STREAM_LAYOUT_HEADER_BYTES + count * STREAM_ENTRY_BYTES;
    encode_response_header(tx, req, (4 + body) as u32);
    write_status(&mut tx[RESP_HDR_LEN..], 0);
    let mut o = RESP_HDR_LEN + 4;
    tx[o..o + 4].copy_from_slice(&(count as u32).to_le_bytes());
    o += 4;
    for s in streams.iter().take(count) {
        tx[o] = s.kind;
        tx[o + 1] = s.local_index;
        tx[o + 2..o + 4].copy_from_slice(&s.global_index.to_le_bytes());
        tx[o + 4..o + 8].copy_from_slice(&s.mmio_offset.to_le_bytes());
        o += STREAM_ENTRY_BYTES;
    }
    let _ = mk_ipc_send(KERNEL_REPLY_ENDPOINT, tx.as_ptr(), RESP_HDR_LEN + 4 + body);
}
