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

use crate::crypto::application::vault::{
    retrieve_key, get_signing_key, get_public_key, list_vault_keys,
};
use crate::crypto::{ed25519, blake3_hash, chacha20poly1305};
use crate::shell::output::print_line;
use crate::shell::commands::utils::trim_bytes;
use crate::graphics::framebuffer::{
    COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW, COLOR_RED,
};

use super::state::check_vault_unsealed;
use super::format::{print_hex_key, print_hex_signature, print_hex_nonce, print_hex_data};

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

pub fn cmd_vault_verify(cmd: &[u8]) {
    if !check_vault_unsealed() {
        return;
    }

    let args = if cmd.len() > 13 {
        trim_bytes(&cmd[13..])
    } else {
        print_line(b"Usage: vault-verify <message>", COLOR_TEXT_DIM);
        print_line(b"Verifies last signature against vault key", COLOR_TEXT_DIM);
        return;
    };

    if args.is_empty() {
        print_line(b"vault-verify: message required", COLOR_RED);
        return;
    }

    let keypairs = list_vault_keys();
    if keypairs.is_empty() {
        print_line(b"No verification keys in vault", COLOR_YELLOW);
        return;
    }

    let key_id = keypairs[0];
    let public_key = match get_public_key(key_id) {
        Some(k) => k,
        None => {
            print_line(b"Failed to retrieve public key", COLOR_RED);
            return;
        }
    };

    print_line(b"Public key found:", COLOR_TEXT);
    print_hex_key(&public_key);
    print_line(b"", COLOR_TEXT);
    print_line(b"Ready to verify signatures", COLOR_GREEN);
}

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

pub fn cmd_vault_decrypt(cmd: &[u8]) {
    if !check_vault_unsealed() {
        return;
    }

    let hex_data = if cmd.len() > 14 {
        trim_bytes(&cmd[14..])
    } else {
        print_line(b"Usage: vault-decrypt <hex-ciphertext>", COLOR_TEXT_DIM);
        print_line(b"Decrypts ChaCha20-Poly1305 ciphertext", COLOR_TEXT_DIM);
        print_line(b"", COLOR_TEXT);
        print_line(b"Format: <24-char-nonce-hex><ciphertext-hex>", COLOR_TEXT_DIM);
        return;
    };

    if hex_data.len() < 24 {
        print_line(b"Ciphertext too short (need nonce + data)", COLOR_RED);
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

    print_line(b"Decryption requires proper nonce + ciphertext", COLOR_TEXT_DIM);
    print_line(b"Use output from vault-encrypt command", COLOR_TEXT_DIM);
}
