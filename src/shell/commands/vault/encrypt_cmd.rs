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

/* encrypts data with chacha20-poly1305 using vault key */

use crate::crypto::application::vault::retrieve_key;
use crate::crypto::chacha20poly1305;
use crate::display::framebuffer::{COLOR_GREEN, COLOR_RED, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_YELLOW};
use crate::shell::commands::utils::trim_bytes;
use crate::shell::output::print_line;

use super::format::{print_hex_data, print_hex_nonce};
use super::state::check_vault_unsealed;

pub fn cmd_vault_encrypt(cmd: &[u8]) {
    if !check_vault_unsealed() {
        return;
    }

    let data = if cmd.len() > 14 {
        trim_bytes(&cmd[14..])
    } else {
        print_line(b"Usage: vault-encrypt <data>", COLOR_TEXT_DIM);
        print_line(b"Encrypts data with ChaCha20-Poly1305", COLOR_TEXT_DIM);
        return;
    };

    if data.is_empty() {
        print_line(b"vault-encrypt: data required", COLOR_RED);
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

    let mut nonce = [0u8; 12];
    crate::crypto::application::vault::generate_random_bytes(&mut nonce).ok();

    match chacha20poly1305::aead_encrypt(&key, &nonce, b"vault", data) {
        Ok(ciphertext) => {
            print_line(b"Encrypting with ChaCha20-Poly1305...", COLOR_TEXT);
            print_line(b"", COLOR_TEXT);

            print_line(b"Nonce (12 bytes):", COLOR_TEXT_DIM);
            print_hex_nonce(&nonce);

            print_line(b"", COLOR_TEXT);
            print_line(b"Ciphertext:", COLOR_TEXT_WHITE);
            print_hex_data(&ciphertext);

            print_line(b"", COLOR_TEXT);
            print_line(b"Encrypted successfully", COLOR_GREEN);
        }
        Err(_) => {
            print_line(b"Encryption failed", COLOR_RED);
        }
    }
}
