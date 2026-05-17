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

use nonos_libc::mk_ipc_call;

const NCMP: u32 = 0x4E43_4D50;
const VERSION: u16 = 1;
const HDR: usize = 20;
const OP_SCENE_SUBMIT: u16 = 0x0002;
const OP_INPUT_SUBSCRIBE: u16 = 0x0005;

fn header(tx: &mut [u8], op: u16, request_id: u32, body_len: u32) {
    tx[0..4].copy_from_slice(&NCMP.to_le_bytes());
    tx[4..6].copy_from_slice(&VERSION.to_le_bytes());
    tx[6..8].copy_from_slice(&op.to_le_bytes());
    tx[12..16].copy_from_slice(&request_id.to_le_bytes());
    tx[16..20].copy_from_slice(&body_len.to_le_bytes());
}

fn ok(rx: &[u8], rc: i64) -> bool {
    rc > 0 && rx.len() >= HDR + 4 && i32::from_le_bytes([rx[20], rx[21], rx[22], rx[23]]) == 0
}

pub fn scene_submit(
    port: u32,
    request_id: u32,
    handle: u64,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    z: u32,
) -> bool {
    let mut tx = [0u8; HDR + 32];
    header(&mut tx, OP_SCENE_SUBMIT, request_id, 32);
    tx[20..28].copy_from_slice(&handle.to_le_bytes());
    tx[28..32].copy_from_slice(&x.to_le_bytes());
    tx[32..36].copy_from_slice(&y.to_le_bytes());
    tx[36..40].copy_from_slice(&w.to_le_bytes());
    tx[40..44].copy_from_slice(&h.to_le_bytes());
    tx[44..48].copy_from_slice(&z.to_le_bytes());
    let mut rx = [0u8; HDR + 4];
    let rc = mk_ipc_call(port as u64, tx.as_ptr(), tx.len(), rx.as_mut_ptr(), rx.len());
    ok(&rx, rc)
}

pub fn input_subscribe(port: u32, request_id: u32) -> bool {
    let mut tx = [0u8; HDR];
    header(&mut tx, OP_INPUT_SUBSCRIBE, request_id, 0);
    let mut rx = [0u8; HDR + 4];
    let rc = mk_ipc_call(port as u64, tx.as_ptr(), tx.len(), rx.as_mut_ptr(), rx.len());
    ok(&rx, rc)
}
