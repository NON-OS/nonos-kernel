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

use super::types::Poly1305;

impl Poly1305 {
    pub(crate) fn new(key: &[u8; 32]) -> Self {
        let mut r = [0u8; 16];
        r.copy_from_slice(&key[0..16]);

        r[3] &= 0x0f;
        r[7] &= 0x0f;
        r[11] &= 0x0f;
        r[15] &= 0x0f;
        r[4] &= 0xfc;
        r[8] &= 0xfc;
        r[12] &= 0xfc;

        let t0 = u32::from_le_bytes([r[0], r[1], r[2], r[3]]);
        let t1 = u32::from_le_bytes([r[4], r[5], r[6], r[7]]);
        let t2 = u32::from_le_bytes([r[8], r[9], r[10], r[11]]);
        let t3 = u32::from_le_bytes([r[12], r[13], r[14], r[15]]);

        let r0 = t0 & 0x3ffffff;
        let r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
        let r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
        let r3 = ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
        let r4 = t3 >> 8;

        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let mut s = [0u8; 16];
        s.copy_from_slice(&key[16..32]);

        Self {
            h0: 0,
            h1: 0,
            h2: 0,
            h3: 0,
            h4: 0,
            r0,
            r1,
            r2,
            r3,
            r4,
            s1,
            s2,
            s3,
            s4,
            s,
            buffer: [0u8; 16],
            buffer_len: 0,
        }
    }

    pub(super) fn block(&mut self, msg: &[u8], hibit: u32) {
        let t0 = u32::from_le_bytes([msg[0], msg[1], msg[2], msg[3]]);
        let t1 = u32::from_le_bytes([msg[4], msg[5], msg[6], msg[7]]);
        let t2 = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
        let t3 = u32::from_le_bytes([msg[12], msg[13], msg[14], msg[15]]);

        self.h0 = self.h0.wrapping_add(t0 & 0x3ffffff);
        self.h1 = self.h1.wrapping_add(((t0 >> 26) | (t1 << 6)) & 0x3ffffff);
        self.h2 = self.h2.wrapping_add(((t1 >> 20) | (t2 << 12)) & 0x3ffffff);
        self.h3 = self.h3.wrapping_add(((t2 >> 14) | (t3 << 18)) & 0x3ffffff);
        self.h4 = self.h4.wrapping_add((t3 >> 8) | hibit);

        let d0 = (self.h0 as u64) * (self.r0 as u64)
            + (self.h1 as u64) * (self.s4 as u64)
            + (self.h2 as u64) * (self.s3 as u64)
            + (self.h3 as u64) * (self.s2 as u64)
            + (self.h4 as u64) * (self.s1 as u64);

        let d1 = (self.h0 as u64) * (self.r1 as u64)
            + (self.h1 as u64) * (self.r0 as u64)
            + (self.h2 as u64) * (self.s4 as u64)
            + (self.h3 as u64) * (self.s3 as u64)
            + (self.h4 as u64) * (self.s2 as u64);

        let d2 = (self.h0 as u64) * (self.r2 as u64)
            + (self.h1 as u64) * (self.r1 as u64)
            + (self.h2 as u64) * (self.r0 as u64)
            + (self.h3 as u64) * (self.s4 as u64)
            + (self.h4 as u64) * (self.s3 as u64);

        let d3 = (self.h0 as u64) * (self.r3 as u64)
            + (self.h1 as u64) * (self.r2 as u64)
            + (self.h2 as u64) * (self.r1 as u64)
            + (self.h3 as u64) * (self.r0 as u64)
            + (self.h4 as u64) * (self.s4 as u64);

        let d4 = (self.h0 as u64) * (self.r4 as u64)
            + (self.h1 as u64) * (self.r3 as u64)
            + (self.h2 as u64) * (self.r2 as u64)
            + (self.h3 as u64) * (self.r1 as u64)
            + (self.h4 as u64) * (self.r0 as u64);

        let mut c: u32;
        c = (d0 >> 26) as u32;
        self.h0 = (d0 as u32) & 0x3ffffff;
        let d1 = d1 + c as u64;
        c = (d1 >> 26) as u32;
        self.h1 = (d1 as u32) & 0x3ffffff;
        let d2 = d2 + c as u64;
        c = (d2 >> 26) as u32;
        self.h2 = (d2 as u32) & 0x3ffffff;
        let d3 = d3 + c as u64;
        c = (d3 >> 26) as u32;
        self.h3 = (d3 as u32) & 0x3ffffff;
        let d4 = d4 + c as u64;
        c = (d4 >> 26) as u32;
        self.h4 = (d4 as u32) & 0x3ffffff;

        self.h0 = self.h0.wrapping_add(c * 5);
        c = self.h0 >> 26;
        self.h0 &= 0x3ffffff;
        self.h1 = self.h1.wrapping_add(c);
    }
}
