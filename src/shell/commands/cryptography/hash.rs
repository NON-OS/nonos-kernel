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

use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_GREEN, COLOR_YELLOW};
use crate::shell::commands::utils::trim_bytes;

use super::util::{split_first_word, print_hash_hex, print_hash_hex_long};

pub fn cmd_hash(cmd: &[u8]) {
    let args = if cmd.len() > 5 {
        trim_bytes(&cmd[5..])
    } else {
        print_line(b"Cryptographic Hash Functions:", COLOR_TEXT_WHITE);
        print_line(b"============================================", COLOR_TEXT_DIM);
        print_line(b"Usage: hash <algorithm> <data>", COLOR_TEXT_DIM);
        print_line(b"", COLOR_TEXT);
        print_line(b"Algorithms:", COLOR_TEXT_WHITE);
        print_line(b"  blake3    BLAKE3 (256-bit, fast)", COLOR_GREEN);
        print_line(b"  sha256    SHA-256 (256-bit)", COLOR_TEXT);
        print_line(b"  sha512    SHA-512 (512-bit)", COLOR_TEXT);
        print_line(b"  sha3      SHA3-256 (256-bit)", COLOR_TEXT);
        print_line(b"", COLOR_TEXT);
        print_line(b"Example: hash blake3 hello", COLOR_TEXT_DIM);
        return;
    };

    let (algo, data) = split_first_word(args);

    if data.is_empty() {
        print_line(b"hash: data required", COLOR_YELLOW);
        return;
    }

    match algo {
        b"blake3" => {
            use crate::crypto::hash::blake3::blake3_hash;
            let hash = blake3_hash(data);
            print_line(b"BLAKE3:", COLOR_TEXT_WHITE);
            print_hash_hex(&hash);
        }
        b"sha256" => {
            use crate::crypto::hash::sha256::sha256_hash;
            let hash = sha256_hash(data);
            print_line(b"SHA-256:", COLOR_TEXT_WHITE);
            print_hash_hex(&hash);
        }
        b"sha512" => {
            use crate::crypto::hash::sha512::sha512_hash;
            let hash = sha512_hash(data);
            print_line(b"SHA-512:", COLOR_TEXT_WHITE);
            print_hash_hex_long(&hash);
        }
        b"sha3" => {
            use crate::crypto::hash::sha3::sha3_256;
            let hash = sha3_256(data);
            print_line(b"SHA3-256:", COLOR_TEXT_WHITE);
            print_hash_hex(&hash);
        }
        _ => {
            print_line(b"hash: unknown algorithm", COLOR_YELLOW);
            print_line(b"Use: blake3, sha256, sha512, sha3", COLOR_TEXT_DIM);
        }
    }
}
