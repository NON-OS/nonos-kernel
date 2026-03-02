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

extern crate alloc;

use alloc::vec::Vec;

use crate::crypto::application::vault::{retrieve_key, store_key, list_keys, list_vault_keys};
use crate::crypto::blake3_hash;
use crate::shell::output::print_line;
use crate::shell::commands::utils::trim_bytes;
use crate::graphics::framebuffer::{
    COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_RED, COLOR_ACCENT,
};

use super::state::check_vault_unsealed;
use super::format::{print_key_count, print_key_id, print_keypair_id, print_hex_key};

pub fn cmd_vault_derive(cmd: &[u8]) {
    if !check_vault_unsealed() {
        return;
    }

    let context = if cmd.len() > 13 {
        trim_bytes(&cmd[13..])
    } else {
        print_line(b"Usage: vault-derive <context>", COLOR_TEXT_DIM);
        print_line(b"", COLOR_TEXT);
        print_line(b"Derives a key from vault master key", COLOR_TEXT_DIM);
        print_line(b"Context: purpose identifier string", COLOR_TEXT_DIM);
        print_line(b"", COLOR_TEXT);
        print_line(b"Example: vault-derive encryption", COLOR_TEXT_DIM);
        return;
    };

    if context.is_empty() {
        print_line(b"vault-derive: context required", COLOR_RED);
        return;
    }

    let master_key = match retrieve_key("master") {
        Ok(k) => k,
        Err(_) => {
            print_line(b"No master key found", COLOR_RED);
            return;
        }
    };

    let mut derive_input = Vec::with_capacity(master_key.len() + context.len());
    derive_input.extend_from_slice(&master_key);
    derive_input.extend_from_slice(context);

    let derived_key = blake3_hash(&derive_input);

    let context_str = core::str::from_utf8(context).unwrap_or("unknown");
    if let Err(_) = store_key(context_str, &derived_key) {
        print_line(b"Failed to store derived key", COLOR_RED);
        return;
    }

    let mut line = [0u8; 64];
    line[..22].copy_from_slice(b"Deriving key for:     ");
    let ctx_len = context.len().min(32);
    line[22..22+ctx_len].copy_from_slice(&context[..ctx_len]);
    print_line(&line[..22+ctx_len], COLOR_TEXT);

    print_line(b"", COLOR_TEXT);
    print_line(b"Using: BLAKE3-HKDF", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);
    print_line(b"Derived Key (256-bit):", COLOR_TEXT_WHITE);
    print_hex_key(&derived_key);
    print_line(b"", COLOR_TEXT);
    print_line(b"Key stored in vault (RAM only)", COLOR_GREEN);
}

pub fn cmd_vault_keys() {
    if !check_vault_unsealed() {
        return;
    }

    print_line(b"Vault Key Inventory:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);

    print_line(b"String Keys:", COLOR_ACCENT);
    let string_keys = list_keys().unwrap_or_default();
    if string_keys.is_empty() {
        print_line(b"  (none)", COLOR_TEXT_DIM);
    } else {
        for key_id in string_keys.iter() {
            print_key_id(key_id.as_bytes());
        }
    }

    print_line(b"", COLOR_TEXT);
    print_line(b"Keypairs (Ed25519):", COLOR_ACCENT);
    let keypairs = list_vault_keys();
    if keypairs.is_empty() {
        print_line(b"  (none)", COLOR_TEXT_DIM);
    } else {
        for key_id in keypairs.iter() {
            print_keypair_id(*key_id);
        }
    }

    print_line(b"", COLOR_TEXT);
    print_key_count(b"Total string keys: ", string_keys.len());
    print_key_count(b"Total keypairs:    ", keypairs.len());
    print_line(b"", COLOR_TEXT);
    print_line(b"Generate keys with: genkey ed25519", COLOR_TEXT_DIM);
    print_line(b"Derive keys with:   vault-derive <ctx>", COLOR_TEXT_DIM);
}
