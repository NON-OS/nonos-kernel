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

use core::convert::TryInto;
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

pub type Hash512 = [u8; 64];

const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

const INITIAL_STATE: [u64; 8] = [
    0x6a09e667f3bcc908u64,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

pub struct Sha512 {
    state: [u64; 8],
    buffer: [u8; 128],
    buffer_len: usize,
    bit_len: u128,
}

impl Sha512 {
    #[inline]
    pub fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            buffer: [0u8; 128],
            buffer_len: 0,
            bit_len: 0,
        }
    }

    pub fn reset(&mut self) {
        for v in &mut self.state {
            unsafe { ptr::write_volatile(v, 0) };
        }
        for b in &mut self.buffer {
            unsafe { ptr::write_volatile(b, 0) };
        }
        unsafe { ptr::write_volatile(&mut self.bit_len, 0) };
        compiler_fence(Ordering::SeqCst);

        self.state = INITIAL_STATE;
        self.buffer_len = 0;
        self.bit_len = 0;
    }

    pub fn update(&mut self, mut input: &[u8]) {
        self.bit_len = self.bit_len.wrapping_add((input.len() as u128) * 8);

        if self.buffer_len != 0 {
            let to_copy = core::cmp::min(128 - self.buffer_len, input.len());
            let dst = &mut self.buffer[self.buffer_len..self.buffer_len + to_copy];
            dst.copy_from_slice(&input[..to_copy]);
            self.buffer_len += to_copy;
            input = &input[to_copy..];

            if self.buffer_len == 128 {
                let block: [u8; 128] = self.buffer.clone().try_into().expect("128 bytes");
                self.process_block(&block);
                self.buffer_len = 0;
            }
        }

        while input.len() >= 128 {
            let block: &[u8; 128] = (&input[..128]).try_into().expect("128 bytes");
            self.process_block(block);
            input = &input[128..];
        }

        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffer_len = input.len();
        }
    }

    pub fn finalize(mut self) -> Hash512 {
        let mut pad_buf = [0u8; 256];
        pad_buf[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);

        pad_buf[self.buffer_len] = 0x80;

        let len_after_1 = self.buffer_len + 1;
        let pad_zeros = if len_after_1 <= 112 {
            112 - len_after_1
        } else {
            (128 - len_after_1) + 112
        };

        let total_pad = 1 + pad_zeros + 16;
        let total_len = self.buffer_len + total_pad;

        let bit_len_be = self.bit_len.to_be_bytes();
        let len_pos = self.buffer_len + 1 + pad_zeros;
        pad_buf[len_pos..len_pos + 16].copy_from_slice(&bit_len_be);

        let mut offset = 0;
        while offset < total_len {
            let chunk: &[u8; 128] = (&pad_buf[offset..offset + 128])
                .try_into()
                .expect("128 bytes chunk");
            self.process_block(chunk);
            offset += 128;
        }

        let mut out = [0u8; 64];
        for (i, &v) in self.state.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&v.to_be_bytes());
        }

        for v in &mut self.state {
            unsafe { ptr::write_volatile(v, 0) };
        }
        for b in &mut self.buffer {
            unsafe { ptr::write_volatile(b, 0) };
        }
        unsafe { ptr::write_volatile(&mut self.bit_len, 0) };
        self.buffer_len = 0;
        compiler_fence(Ordering::SeqCst);

        out
    }

    fn process_block(&mut self, block: &[u8; 128]) {
        let mut w = [0u64; 80];

        for i in 0..16 {
            let idx = i * 8;
            w[i] = u64::from_be_bytes([
                block[idx],
                block[idx + 1],
                block[idx + 2],
                block[idx + 3],
                block[idx + 4],
                block[idx + 5],
                block[idx + 6],
                block[idx + 7],
            ]);
        }

        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

impl Drop for Sha512 {
    fn drop(&mut self) {
        for v in &mut self.state {
            unsafe { ptr::write_volatile(v, 0) };
        }
        for b in &mut self.buffer {
            unsafe { ptr::write_volatile(b, 0) };
        }
        unsafe { ptr::write_volatile(&mut self.bit_len, 0) };
        self.buffer_len = 0;
        compiler_fence(Ordering::SeqCst);
    }
}

pub fn sha512(data: &[u8]) -> Hash512 {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::{sha512, Hash512, Sha512};
    use alloc::vec::Vec;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let s = s.replace(|c: char| c.is_whitespace(), "");
        let mut result = Vec::with_capacity(s.len() / 2);
        for i in (0..s.len()).step_by(2) {
            let byte = u8::from_str_radix(&s[i..i+2], 16).expect("valid hex");
            result.push(byte);
        }
        result
    }

    fn assert_eq_hex(actual: &Hash512, expected_hex: &str) {
        let expected_bytes = hex_to_bytes(expected_hex);
        assert_eq!(&expected_bytes[..], &actual[..]);
    }

    #[test]
    fn test_empty() {
        let digest = sha512(b"");
        assert_eq_hex(
            &digest,
            "cf83e1357eefb8bd
             f1542850d66d8007
             d620e4050b5715dc
             83f4a921d36ce9ce
             47d0d13c5d85f2b0
             ff8318d2877eec2f
             63b931bd47417a81
             a538327af927da3e",
        );
    }

    #[test]
    fn test_abc() {
        let digest = sha512(b"abc");
        assert_eq_hex(
            &digest,
            "ddaf35a193617aba
             cc417349ae204131
             12e6fa4e89a97ea2
             0a9eeee64b55d39a
             2192992a274fc1a8
             36ba3c23a3feebbd
             454d4423643ce80e
             2a9ac94fa54ca49f",
        );
    }

    #[test]
    fn test_quick_brown_fox() {
        let digest = sha512(b"The quick brown fox jumps over the lazy dog");
        assert_eq_hex(
            &digest,
            "07e547d9586f6a73
             f73fbac0435ed769
             51218fb7d0c8d788
             a309d785436bbb64
             2e93a252a954f239
             12547d1e8a3b5ed6
             e1bfd7097821233f
             a0538f3db854fee6",
        );
    }

    #[test]
    fn test_streaming_matches_oneshot() {
        let data = b"abcdefgh0123456789".repeat(100);
        let mut s = Sha512::new();
        for chunk in data.chunks(50) {
            s.update(chunk);
        }
        let out1 = s.finalize();
        let out2 = sha512(&data);
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_partial_buffers_and_boundaries() {
        for len in 0..128 {
            let data = vec![0x5Au8; len];
            let out1 = sha512(&data);
            let mut s = Sha512::new();
            s.update(&data);
            let out2 = s.finalize();
            assert_eq!(out1, out2, "mismatch for len {}", len);
        }
    }
}
