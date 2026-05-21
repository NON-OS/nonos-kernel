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

use nonos_libc::{mk_ipc_call, mk_service_lookup};

use crate::command::output::Output;
use crate::command::wire::{encode_header, HDR_LEN, OP_LIST_APPS};
use crate::term::dimensions::COLS;
use crate::term::util::{copy_into, format_u64};

const MARKET_NAME: &[u8] = b"market";
const RSP_CAP: usize = 4096;

pub fn run(out: &mut Output<'_>, _argv: &[&[u8]]) {
    let mut port = 0u32;
    let mut pid = 0u32;
    let rc = mk_service_lookup(MARKET_NAME.as_ptr(), MARKET_NAME.len(), &mut port, &mut pid);
    if rc != 0 || port == 0 {
        out.writeln(b"  market service not registered");
        return;
    }
    let mut req = [0u8; HDR_LEN];
    encode_header(&mut req, OP_LIST_APPS, 0);
    let mut rsp = [0u8; RSP_CAP];
    let n = mk_ipc_call(port as u64, req.as_ptr(), req.len(), rsp.as_mut_ptr(), rsp.len());
    if n <= 0 {
        let mut line = [0u8; 64];
        let mut k = 0;
        k += copy_into(&mut line[k..], b"  market call failed errno=");
        k += format_u64((-n) as u64, &mut line[k..]);
        out.writeln(&line[..k]);
        return;
    }
    let body_off = 8;
    if (n as usize) < body_off + 4 {
        out.writeln(b"  market: short reply");
        return;
    }
    let count = u32::from_le_bytes([
        rsp[body_off],
        rsp[body_off + 1],
        rsp[body_off + 2],
        rsp[body_off + 3],
    ]);
    let mut header = [0u8; 64];
    let mut hp = 0;
    hp += copy_into(&mut header[hp..], b"market: ");
    hp += format_u64(count as u64, &mut header[hp..]);
    hp += copy_into(&mut header[hp..], b" listing(s)");
    out.writeln(&header[..hp]);
    render_entries(out, &rsp[body_off + 4..n as usize], count);
}

fn render_entries(out: &mut Output<'_>, body: &[u8], count: u32) {
    let mut cursor = 0;
    for _ in 0..count {
        if cursor + 4 > body.len() {
            return;
        }
        let listing_len = u32::from_le_bytes([
            body[cursor],
            body[cursor + 1],
            body[cursor + 2],
            body[cursor + 3],
        ]) as usize;
        cursor += 4;
        if cursor + listing_len > body.len() {
            return;
        }
        let listing = &body[cursor..cursor + listing_len];
        cursor += listing_len;
        if cursor + 32 > body.len() {
            return;
        }
        cursor += 32;
        if cursor + 4 > body.len() {
            return;
        }
        let name_len = u32::from_le_bytes([
            body[cursor],
            body[cursor + 1],
            body[cursor + 2],
            body[cursor + 3],
        ]) as usize;
        cursor += 4;
        if cursor + name_len + 1 > body.len() {
            return;
        }
        let name = &body[cursor..cursor + name_len];
        cursor += name_len;
        let ready = body[cursor] != 0;
        cursor += 1;
        emit_line(out, listing, name, ready);
    }
}

fn emit_line(out: &mut Output<'_>, listing: &[u8], name: &[u8], ready: bool) {
    let mut line = [0u8; COLS];
    let mut n = 0;
    n += copy_into(&mut line[n..], if ready { b"  [ready]   " } else { b"  [pending] " });
    n += copy_into(&mut line[n..], name);
    n += copy_into(&mut line[n..], b"  id=");
    n += copy_into(&mut line[n..], listing);
    out.writeln(&line[..n]);
}
