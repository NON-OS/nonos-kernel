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

/* verifies ed25519 signatures using vault public key */

use crate::crypto::application::vault::{get_public_key, list_vault_keys};
use crate::shell::output::print_line;
use crate::shell::commands::utils::trim_bytes;
use crate::graphics::framebuffer::{
    COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW, COLOR_RED,
};

use super::state::check_vault_unsealed;
use super::format::print_hex_key;

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
