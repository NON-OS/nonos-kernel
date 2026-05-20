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

use super::envelope::call;

const OP_RECV: u16 = 5;

pub struct Datagram<'a> {
    pub src: [u8; 4],
    pub src_port: u16,
    pub payload: &'a [u8],
}

pub fn recv_from(port: u32, local: u16, out: &mut [u8]) -> Result<Datagram<'_>, u16> {
    let n = call(port, OP_RECV, &local.to_le_bytes(), out)?;
    if n < 6 {
        return Err(4);
    }
    let mut src = [0u8; 4];
    src.copy_from_slice(&out[0..4]);
    let src_port = u16::from_le_bytes([out[4], out[5]]);
    Ok(Datagram { src, src_port, payload: &out[6..n] })
}
