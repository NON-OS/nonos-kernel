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

use crate::controller::ControllerInfo;
use crate::protocol::{
    encode_response_header, write_status, Request, CONTROLLER_INFO_PAYLOAD_LEN,
    KERNEL_REPLY_ENDPOINT, RESP_HDR_LEN,
};
use crate::setup::Driver;

pub fn handle(driver: &Driver, req: &Request, tx: &mut [u8]) {
    let info = ControllerInfo::read(driver.regs);
    let payload_len = (4 + CONTROLLER_INFO_PAYLOAD_LEN) as u32;
    encode_response_header(tx, req, payload_len);
    write_status(&mut tx[RESP_HDR_LEN..], 0);
    let mut o = RESP_HDR_LEN + 4;
    put16(tx, &mut o, info.gcap);
    tx[o] = info.vmin;
    tx[o + 1] = info.vmaj;
    o += 2;
    put16(tx, &mut o, info.outpay);
    put16(tx, &mut o, info.inpay);
    put32(tx, &mut o, info.gctl);
    put16(tx, &mut o, info.statests);
    put16(tx, &mut o, info.gsts);
    put32(tx, &mut o, info.intctl);
    put32(tx, &mut o, info.intsts);
    tx[o..o + 4].copy_from_slice(&[
        info.input_streams,
        info.output_streams,
        info.bidi_streams,
        info.addr64,
    ]);
    let _ = mk_ipc_send(KERNEL_REPLY_ENDPOINT, tx.as_ptr(), RESP_HDR_LEN + payload_len as usize);
}

fn put16(tx: &mut [u8], o: &mut usize, v: u16) {
    tx[*o..*o + 2].copy_from_slice(&v.to_le_bytes());
    *o += 2;
}

fn put32(tx: &mut [u8], o: &mut usize, v: u32) {
    tx[*o..*o + 4].copy_from_slice(&v.to_le_bytes());
    *o += 4;
}
