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

use crate::protocol::{
    encode_response_header, write_status, Request, CODEC_ENTRY_BYTES, CODEC_LIST_HEADER_BYTES,
    KERNEL_REPLY_ENDPOINT, RESP_HDR_LEN,
};
use crate::setup::Driver;

pub fn handle(driver: &Driver, req: &Request, tx: &mut [u8]) {
    let count = driver.codecs.iter().filter(|c| c.present != 0).count();
    let body = CODEC_LIST_HEADER_BYTES + count * CODEC_ENTRY_BYTES;
    encode_response_header(tx, req, (4 + body) as u32);
    write_status(&mut tx[RESP_HDR_LEN..], 0);
    let mut o = RESP_HDR_LEN + 4;
    tx[o..o + 4].copy_from_slice(&(count as u32).to_le_bytes());
    o += 4;
    for c in driver.codecs.iter().filter(|c| c.present != 0) {
        tx[o] = c.address;
        tx[o + 1] = c.ok;
        tx[o + 2..o + 4].copy_from_slice(&c.vendor_id.to_le_bytes());
        tx[o + 4..o + 6].copy_from_slice(&c.device_id.to_le_bytes());
        tx[o + 6..o + 8].copy_from_slice(&0u16.to_le_bytes());
        o += CODEC_ENTRY_BYTES;
    }
    let _ = mk_ipc_send(KERNEL_REPLY_ENDPOINT, tx.as_ptr(), RESP_HDR_LEN + 4 + body);
}
