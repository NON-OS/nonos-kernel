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
