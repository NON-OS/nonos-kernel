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
    encode_response_header, write_status, Request, CONTROLLER_INFO_PAYLOAD_LEN,
    KERNEL_REPLY_ENDPOINT, RESP_HDR_LEN,
};
use crate::setup::Driver;

pub fn handle(driver: &Driver, req: &Request, tx: &mut [u8]) {
    let info = crate::controller::ControllerInfo::read(driver.regs);
    let payload_len = (4 + CONTROLLER_INFO_PAYLOAD_LEN) as u32;
    encode_response_header(tx, req, payload_len);
    write_status(&mut tx[RESP_HDR_LEN..], 0);
    let mut o = RESP_HDR_LEN + 4;
    tx[o..o + 4].copy_from_slice(&info.cap.to_le_bytes());
    o += 4;
    tx[o..o + 4].copy_from_slice(&info.ghc.to_le_bytes());
    o += 4;
    tx[o..o + 4].copy_from_slice(&info.pi.to_le_bytes());
    o += 4;
    tx[o..o + 4].copy_from_slice(&info.version.to_le_bytes());
    o += 4;
    tx[o..o + 4].copy_from_slice(&info.cap2.to_le_bytes());
    o += 4;
    tx[o] = info.port_count;
    tx[o + 1] = 0;
    tx[o + 2] = 0;
    tx[o + 3] = 0;
    let _ = mk_ipc_send(KERNEL_REPLY_ENDPOINT, tx.as_ptr(), RESP_HDR_LEN + payload_len as usize);
}
