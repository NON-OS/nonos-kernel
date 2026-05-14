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
    encode_response_header, write_status, Request, IDENTIFY_CONTROLLER_PAYLOAD_LEN,
    KERNEL_REPLY_ENDPOINT, RESP_HDR_LEN,
};
use crate::setup::Driver;

pub fn handle(driver: &Driver, req: &Request, tx: &mut [u8]) {
    let id = driver.identity;
    let payload_len = (4 + IDENTIFY_CONTROLLER_PAYLOAD_LEN) as u32;
    encode_response_header(tx, req, payload_len);
    write_status(&mut tx[RESP_HDR_LEN..], 0);
    let mut o = RESP_HDR_LEN + 4;
    put16(tx, &mut o, id.vendor_id);
    put16(tx, &mut o, id.subsystem_vendor_id);
    copy(tx, &mut o, &id.serial);
    copy(tx, &mut o, &id.model);
    copy(tx, &mut o, &id.firmware);
    put32(tx, &mut o, id.version);
    put16(tx, &mut o, id.optional_admin);
    put32(tx, &mut o, id.namespace_count);
    tx[o] = id.mdts;
    tx[o + 1] = id.sq_entry_size;
    tx[o + 2] = id.cq_entry_size;
    put16_at(tx, o + 3, id.optional_nvm);
    tx[o + 5] = id.volatile_write_cache;
    let _ = mk_ipc_send(KERNEL_REPLY_ENDPOINT, tx.as_ptr(), RESP_HDR_LEN + payload_len as usize);
}

fn copy(tx: &mut [u8], o: &mut usize, src: &[u8]) {
    tx[*o..*o + src.len()].copy_from_slice(src);
    *o += src.len();
}

fn put16(tx: &mut [u8], o: &mut usize, v: u16) {
    put16_at(tx, *o, v);
    *o += 2;
}

fn put16_at(tx: &mut [u8], o: usize, v: u16) {
    tx[o..o + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(tx: &mut [u8], o: &mut usize, v: u32) {
    tx[*o..*o + 4].copy_from_slice(&v.to_le_bytes());
    *o += 4;
}
