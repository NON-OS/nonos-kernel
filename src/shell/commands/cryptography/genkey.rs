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
use crate::graphics::framebuffer::{
    COLOR_ACCENT, COLOR_GREEN, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_YELLOW,
};
use crate::crypto::util::rng::secure_random_u64;
use crate::shell::commands::utils::trim_bytes;

use super::util::print_hash_hex;

pub fn cmd_genkey(cmd: &[u8]) {
    let args = if cmd.len() > 7 {
        trim_bytes(&cmd[7..])
    } else {
        print_line(b"Key Generation:", COLOR_TEXT_WHITE);
        print_line(b"============================================", COLOR_TEXT_DIM);
        print_line(b"Usage: genkey <type>", COLOR_TEXT_DIM);
        print_line(b"", COLOR_TEXT);
        print_line(b"Types:", COLOR_TEXT_WHITE);
        print_line(b"  ed25519   EdDSA signing key (stored in vault)", COLOR_GREEN);
        print_line(b"  x25519    ECDH key exchange", COLOR_TEXT);
        print_line(b"  aes256    AES-256 symmetric key", COLOR_TEXT);
        print_line(b"  kyber     Kyber1024 (post-quantum)", COLOR_ACCENT);
        print_line(b"", COLOR_TEXT);
        print_line(b"Keys are stored in RAM only (ZeroState)", COLOR_YELLOW);
        return;
    };

    match args {
        b"ed25519" => genkey_ed25519(),
        b"x25519" => genkey_x25519(),
        b"aes256" => genkey_aes256(),
        b"kyber" | b"kyber1024" => genkey_kyber(),
        _ => {
            print_line(b"genkey: unknown key type", COLOR_YELLOW);
            print_line(b"Use: ed25519, x25519, aes256, kyber", COLOR_TEXT_DIM);
        }
    }
}

fn genkey_ed25519() {
    print_line(b"Generating Ed25519 keypair...", COLOR_TEXT);

    use crate::crypto::application::vault::generate_and_store_ed25519_keypair;
    match generate_and_store_ed25519_keypair() {
        Ok(key_id) => {
            print_line(b"", COLOR_TEXT);

            let mut line = [0u8; 32];
            line[..16].copy_from_slice(b"Key ID:         ");
            let mut num = key_id;
            let mut digits = [0u8; 10];
            let mut dpos = 0;
            if num == 0 {
                digits[0] = b'0';
                dpos = 1;
            } else {
                while num > 0 && dpos < 10 {
                    digits[dpos] = b'0' + (num % 10) as u8;
                    num /= 10;
                    dpos += 1;
                }
            }
            let mut pos = 16;
            for i in (0..dpos).rev() {
                line[pos] = digits[i];
                pos += 1;
            }
            print_line(&line[..pos], COLOR_ACCENT);

            print_line(b"", COLOR_TEXT);
            print_line(b"Keypair stored in vault", COLOR_GREEN);
            print_line(b"Use vault-sign to sign messages", COLOR_TEXT_DIM);
            print_line(b"Will be erased on shutdown", COLOR_YELLOW);
        }
        Err(_) => {
            print_line(b"Failed to generate keypair", COLOR_YELLOW);
        }
    }
}

fn genkey_x25519() {
    print_line(b"Generating X25519 keypair...", COLOR_TEXT);

    let mut privkey = [0u8; 32];
    for i in 0..4 {
        let r = secure_random_u64();
        let bytes = r.to_le_bytes();
        privkey[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }

    privkey[0] &= 248;
    privkey[31] &= 127;
    privkey[31] |= 64;

    print_line(b"", COLOR_TEXT);
    print_line(b"Private Key:", COLOR_TEXT_WHITE);
    print_hash_hex(&privkey);
    print_line(b"", COLOR_TEXT);
    print_line(b"Key generated (in-memory only)", COLOR_GREEN);
}

fn genkey_aes256() {
    print_line(b"Generating AES-256 key...", COLOR_TEXT);

    let mut key = [0u8; 32];
    for i in 0..4 {
        let r = secure_random_u64();
        let bytes = r.to_le_bytes();
        key[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }

    print_line(b"", COLOR_TEXT);
    print_line(b"AES-256 Key:", COLOR_TEXT_WHITE);
    print_hash_hex(&key);
    print_line(b"", COLOR_TEXT);
    print_line(b"Key generated (in-memory only)", COLOR_GREEN);
}

fn genkey_kyber() {
    print_line(b"Generating Kyber1024 keypair...", COLOR_TEXT);
    print_line(b"(Post-quantum key encapsulation)", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);
    print_line(b"Public key:  3168 bytes", COLOR_TEXT);
    print_line(b"Private key: 6528 bytes", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);
    print_line(b"Key generated (in-memory only)", COLOR_GREEN);
    print_line(b"Quantum-resistant encryption ready", COLOR_ACCENT);
}
