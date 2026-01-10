// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::chacha20::secure_zero_bytes;

pub(crate) struct Poly1305 {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    r0: u32,
    r1: u32,
    r2: u32,
    r3: u32,
    r4: u32,
    s1: u32,
    s2: u32,
    s3: u32,
    s4: u32,
    s: [u8; 16],
    buffer: [u8; 16],
    buffer_len: usize,
}

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

    fn block(&mut self, msg: &[u8], hibit: u32) {
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

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        if self.buffer_len > 0 {
            let need = 16 - self.buffer_len;
            let take = core::cmp::min(need, data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            data = &data[take..];

            if self.buffer_len == 16 {
                let buf_copy = self.buffer;
                self.block(&buf_copy, 1 << 24);
                self.buffer_len = 0;
            }
        }

        while data.len() >= 16 {
            self.block(&data[..16], 1 << 24);
            data = &data[16..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    pub(crate) fn finalize(&mut self) -> [u8; 16] {
        if self.buffer_len > 0 {
            let mut block = [0u8; 16];
            block[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
            block[self.buffer_len] = 1;
            self.block(&block, 0);
        }

        let mut c = self.h1 >> 26;
        self.h1 &= 0x3ffffff;
        self.h2 = self.h2.wrapping_add(c);
        c = self.h2 >> 26;
        self.h2 &= 0x3ffffff;
        self.h3 = self.h3.wrapping_add(c);
        c = self.h3 >> 26;
        self.h3 &= 0x3ffffff;
        self.h4 = self.h4.wrapping_add(c);
        c = self.h4 >> 26;
        self.h4 &= 0x3ffffff;
        self.h0 = self.h0.wrapping_add(c * 5);
        c = self.h0 >> 26;
        self.h0 &= 0x3ffffff;
        self.h1 = self.h1.wrapping_add(c);

        let mut g0 = self.h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x3ffffff;
        let mut g1 = self.h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x3ffffff;
        let mut g2 = self.h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x3ffffff;
        let mut g3 = self.h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x3ffffff;
        let g4 = self.h4.wrapping_add(c).wrapping_sub(1 << 26);

        let mask = ((g4 >> 31) as u32).wrapping_sub(1);
        let mask = !mask;

        self.h0 = (self.h0 & mask) | (g0 & !mask);
        self.h1 = (self.h1 & mask) | (g1 & !mask);
        self.h2 = (self.h2 & mask) | (g2 & !mask);
        self.h3 = (self.h3 & mask) | (g3 & !mask);
        self.h4 = (self.h4 & mask) | (g4 & !mask);

        let h0 = self.h0;
        let h1 = self.h1;
        let h2 = self.h2;
        let h3 = self.h3;
        let h4 = self.h4;

        let mut f = [0u8; 16];
        let t = h0 | (h1 << 26);
        f[0..4].copy_from_slice(&(t as u32).to_le_bytes());
        let t = (h1 >> 6) | (h2 << 20);
        f[4..8].copy_from_slice(&(t as u32).to_le_bytes());
        let t = (h2 >> 12) | (h3 << 14);
        f[8..12].copy_from_slice(&(t as u32).to_le_bytes());
        let t = (h3 >> 18) | (h4 << 8);
        f[12..16].copy_from_slice(&(t as u32).to_le_bytes());

        let mut tag = [0u8; 16];
        let mut carry = 0u16;
        for i in 0..16 {
            let v = f[i] as u16 + self.s[i] as u16 + carry;
            tag[i] = v as u8;
            carry = v >> 8;
        }

        tag
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        // SAFETY: We have exclusive mutable access to self, and volatile writes ensure
        // the compiler cannot optimize away this zeroing of sensitive cryptographic state.
        unsafe {
            core::ptr::write_volatile(&mut self.h0, 0);
            core::ptr::write_volatile(&mut self.h1, 0);
            core::ptr::write_volatile(&mut self.h2, 0);
            core::ptr::write_volatile(&mut self.h3, 0);
            core::ptr::write_volatile(&mut self.h4, 0);
            core::ptr::write_volatile(&mut self.r0, 0);
            core::ptr::write_volatile(&mut self.r1, 0);
            core::ptr::write_volatile(&mut self.r2, 0);
            core::ptr::write_volatile(&mut self.r3, 0);
            core::ptr::write_volatile(&mut self.r4, 0);
            core::ptr::write_volatile(&mut self.s1, 0);
            core::ptr::write_volatile(&mut self.s2, 0);
            core::ptr::write_volatile(&mut self.s3, 0);
            core::ptr::write_volatile(&mut self.s4, 0);
            core::ptr::write_volatile(&mut self.buffer_len, 0);
        }
        secure_zero_bytes(&mut self.s);
        secure_zero_bytes(&mut self.buffer);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

pub fn poly1305_mac(msg: &[u8], key: &[u8; 32]) -> [u8; 16] {
    let mut poly = Poly1305::new(key);
    poly.update(msg);
    poly.finalize()
}
