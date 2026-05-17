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

const NWMP: u32 = 0x4E57_4D50;
const VERSION: u16 = 1;
const HDR: usize = 20;
const OP_WINDOW_OPEN: u16 = 0x0002;
const KIND_NORMAL: u32 = 0;

pub fn open_window(port: u32, request_id: u32, window_id: u32, x: u32, y: u32, w: u32, h: u32) -> bool {
    let mut tx = [0u8; HDR + 24];
    tx[0..4].copy_from_slice(&NWMP.to_le_bytes());
    tx[4..6].copy_from_slice(&VERSION.to_le_bytes());
    tx[6..8].copy_from_slice(&OP_WINDOW_OPEN.to_le_bytes());
    tx[12..16].copy_from_slice(&request_id.to_le_bytes());
    tx[16..20].copy_from_slice(&24u32.to_le_bytes());
    tx[20..24].copy_from_slice(&window_id.to_le_bytes());
    tx[24..28].copy_from_slice(&KIND_NORMAL.to_le_bytes());
    tx[28..32].copy_from_slice(&x.to_le_bytes());
    tx[32..36].copy_from_slice(&y.to_le_bytes());
    tx[36..40].copy_from_slice(&w.to_le_bytes());
    tx[40..44].copy_from_slice(&h.to_le_bytes());
    let mut rx = [0u8; HDR + 4];
    let rc = mk_ipc_call(port as u64, tx.as_ptr(), tx.len(), rx.as_mut_ptr(), rx.len());
    rc > 0 && i32::from_le_bytes([rx[20], rx[21], rx[22], rx[23]]) == 0
}
