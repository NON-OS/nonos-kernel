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

/* decrypts chacha20-poly1305 ciphertext using vault key */

extern crate alloc;

use crate::crypto::application::vault::retrieve_key;
use crate::crypto::chacha20poly1305;
use crate::graphics::framebuffer::{
    COLOR_GREEN, COLOR_RED, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_YELLOW,
};
use crate::shell::commands::utils::trim_bytes;
use crate::shell::output::print_line;
use alloc::vec::Vec;

use super::state::check_vault_unsealed;

pub fn cmd_vault_decrypt(cmd: &[u8]) {
    if !check_vault_unsealed() {
        return;
    }

    let hex_data = if cmd.len() > 14 {
        trim_bytes(&cmd[14..])
    } else {
        print_line(b"Usage: vault-decrypt <nonce-hex><ciphertext-hex>", COLOR_TEXT_DIM);
        print_line(b"Decrypts ChaCha20-Poly1305 ciphertext", COLOR_TEXT_DIM);
        print_line(b"", COLOR_TEXT);
        print_line(b"Nonce: 24 hex chars (12 bytes)", COLOR_TEXT_DIM);
        print_line(b"Ciphertext: remaining hex data", COLOR_TEXT_DIM);
        return;
    };

    if hex_data.len() < 24 {
        print_line(b"Input too short (need nonce + ciphertext)", COLOR_RED);
        return;
    }

    let encryption_key = match retrieve_key("encryption") {
        Ok(k) => k,
        Err(_) => {
            print_line(b"No encryption key found", COLOR_YELLOW);
            print_line(b"Derive one with: vault-derive encryption", COLOR_TEXT_DIM);
            return;
        }
    };

    if encryption_key.len() < 32 {
        print_line(b"Invalid encryption key", COLOR_RED);
        return;
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&encryption_key[..32]);

    let nonce_hex = &hex_data[..24];
    let ciphertext_hex = &hex_data[24..];

    let nonce = match parse_hex_12(nonce_hex) {
        Some(n) => n,
        None => {
            print_line(b"Invalid nonce hex", COLOR_RED);
            return;
        }
    };

    let ciphertext = match parse_hex_bytes(ciphertext_hex) {
        Some(ct) => ct,
        None => {
            print_line(b"Invalid ciphertext hex", COLOR_RED);
            return;
        }
    };

    if ciphertext.len() < 16 {
        print_line(b"Ciphertext too short (need auth tag)", COLOR_RED);
        return;
    }

    print_line(b"Decrypting with ChaCha20-Poly1305...", COLOR_TEXT);

    match chacha20poly1305::aead_decrypt(&key, &nonce, b"vault", &ciphertext) {
        Ok(plaintext) => {
            print_line(b"", COLOR_TEXT);
            print_line(b"Plaintext:", COLOR_TEXT_WHITE);

            if plaintext.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
                print_line(&plaintext, COLOR_GREEN);
            } else {
                print_hex_output(&plaintext);
            }

            print_line(b"", COLOR_TEXT);
            print_line(b"Decrypted successfully", COLOR_GREEN);
        }
        Err(_) => {
            print_line(b"Decryption failed (auth tag invalid)", COLOR_RED);
            print_line(b"Wrong key or corrupted ciphertext", COLOR_TEXT_DIM);
        }
    }
}

fn parse_hex_12(hex: &[u8]) -> Option<[u8; 12]> {
    if hex.len() != 24 {
        return None;
    }

    let mut result = [0u8; 12];
    for i in 0..12 {
        let high = hex_digit(hex[i * 2])?;
        let low = hex_digit(hex[i * 2 + 1])?;
        result[i] = (high << 4) | low;
    }
    Some(result)
}

fn parse_hex_bytes(hex: &[u8]) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }

    let mut result = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let high = hex_digit(hex[i])?;
        let low = hex_digit(hex[i + 1])?;
        result.push((high << 4) | low);
    }
    Some(result)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn print_hex_output(data: &[u8]) {
    use alloc::string::String;

    let mut hex = String::with_capacity(data.len() * 2);
    for byte in data {
        hex.push_str(&alloc::format!("{:02x}", byte));
    }
    print_line(hex.as_bytes(), COLOR_TEXT_DIM);
}
