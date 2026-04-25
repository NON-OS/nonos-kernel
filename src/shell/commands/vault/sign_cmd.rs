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

/* signs messages with vault ed25519 key */

use crate::crypto::application::vault::{get_signing_key, list_vault_keys};
use crate::crypto::{blake3_hash, ed25519};
use crate::graphics::framebuffer::{
    COLOR_GREEN, COLOR_RED, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_YELLOW,
};
use crate::shell::commands::utils::trim_bytes;
use crate::shell::output::print_line;

use super::format::{print_hex_key, print_hex_signature};
use super::state::check_vault_unsealed;

pub fn cmd_vault_sign(cmd: &[u8]) {
    if !check_vault_unsealed() {
        return;
    }

    let message = if cmd.len() > 11 {
        trim_bytes(&cmd[11..])
    } else {
        print_line(b"Usage: vault-sign <message>", COLOR_TEXT_DIM);
        print_line(b"Signs message with vault Ed25519 key", COLOR_TEXT_DIM);
        return;
    };

    if message.is_empty() {
        print_line(b"vault-sign: message required", COLOR_RED);
        return;
    }

    let keypairs = list_vault_keys();
    if keypairs.is_empty() {
        print_line(b"No signing keys in vault", COLOR_YELLOW);
        print_line(b"Generate one with: genkey ed25519", COLOR_TEXT_DIM);
        return;
    }

    let key_id = keypairs[0];
    let signing_key = match get_signing_key(key_id) {
        Some(k) => k,
        None => {
            print_line(b"Failed to retrieve signing key", COLOR_RED);
            return;
        }
    };

    let keypair = ed25519::KeyPair::from_seed(signing_key);
    let signature = ed25519::sign(&keypair, message);

    print_line(b"Signing with Ed25519...", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);
    print_line(b"Message hash (BLAKE3):", COLOR_TEXT_DIM);
    let msg_hash = blake3_hash(message);
    print_hex_key(&msg_hash);

    print_line(b"", COLOR_TEXT);
    print_line(b"Signature (64 bytes):", COLOR_TEXT_WHITE);
    print_hex_signature(&signature.to_bytes());

    print_line(b"", COLOR_TEXT);
    print_line(b"Signed successfully", COLOR_GREEN);
}
