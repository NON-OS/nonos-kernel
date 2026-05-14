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

use crate::constants::MAX_PORTS;
use crate::protocol::{
    encode_response_header, write_status, Request, KERNEL_REPLY_ENDPOINT, PORT_ENTRY_BYTES,
    PORT_LIST_HEADER_BYTES, RESP_HDR_LEN,
};
use crate::setup::Driver;

pub fn handle(driver: &Driver, req: &Request, tx: &mut [u8]) {
    let count = core::cmp::min(driver.info.port_count as usize, MAX_PORTS);
    let body = PORT_LIST_HEADER_BYTES + count * PORT_ENTRY_BYTES;
    encode_response_header(tx, req, (4 + body) as u32);
    write_status(&mut tx[RESP_HDR_LEN..], 0);
    let mut o = RESP_HDR_LEN + 4;
    tx[o..o + 4].copy_from_slice(&(count as u32).to_le_bytes());
    o += 4;
    for p in driver.ports.iter().take(count) {
        tx[o] = p.index;
        tx[o + 1] = p.implemented;
        tx[o + 2] = p.present;
        tx[o + 3] = p.kind;
        put32(tx, o + 4, p.ssts);
        put32(tx, o + 8, p.sig);
        put32(tx, o + 12, p.interrupt_status);
        put32(tx, o + 16, p.command_status);
        put32(tx, o + 20, p.task_file_data);
        put32(tx, o + 24, p.sata_error);
        put32(tx, o + 28, p.active_commands);
        put32(tx, o + 32, p.issued_commands);
        o += PORT_ENTRY_BYTES;
    }
    let _ = mk_ipc_send(KERNEL_REPLY_ENDPOINT, tx.as_ptr(), RESP_HDR_LEN + 4 + body);
}

fn put32(tx: &mut [u8], off: usize, v: u32) {
    tx[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
