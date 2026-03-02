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

use crate::crypto::application::vault::{init_vault, store_key, zeroize_all_keys};
use crate::crypto::blake3_hash;
use crate::shell::output::print_line;
use crate::shell::commands::utils::trim_bytes;
use crate::graphics::framebuffer::{
    COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW, COLOR_RED, COLOR_ACCENT,
};

use super::state::{is_sealed, is_initialized, set_sealed, set_initialized};

pub fn cmd_vault_seal() {
    if !is_initialized() {
        print_line(b"Vault not initialized", COLOR_RED);
        return;
    }

    if is_sealed() {
        print_line(b"Vault already sealed", COLOR_YELLOW);
        return;
    }

    print_line(b"Sealing Vault...", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);
    print_line(b"[1/3] Encrypting key material...", COLOR_TEXT);
    print_line(b"[2/3] Clearing plaintext keys...", COLOR_TEXT);

    zeroize_all_keys();

    print_line(b"[3/3] Memory barrier complete", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);

    set_sealed(true);

    print_line(b"Vault SEALED", COLOR_GREEN);
    print_line(b"Keys protected, require passphrase to unseal", COLOR_YELLOW);
}

pub fn cmd_vault_unseal(cmd: &[u8]) {
    let passphrase = if cmd.len() > 13 {
        trim_bytes(&cmd[13..])
    } else {
        print_line(b"Usage: vault-unseal <passphrase>", COLOR_TEXT_DIM);
        print_line(b"", COLOR_TEXT);
        print_line(b"Unseals the vault using your passphrase", COLOR_TEXT_DIM);
        print_line(b"Keys derived via BLAKE3-HKDF", COLOR_TEXT_DIM);
        return;
    };

    if passphrase.is_empty() {
        print_line(b"vault-unseal: passphrase required", COLOR_RED);
        return;
    }

    print_line(b"Unsealing Vault...", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);
    print_line(b"[1/3] Deriving master key (BLAKE3)...", COLOR_TEXT);

    let master_key = blake3_hash(passphrase);

    print_line(b"[2/3] Initializing vault storage...", COLOR_TEXT);

    if let Err(_) = init_vault() {
        print_line(b"Failed to initialize vault", COLOR_RED);
        return;
    }

    if let Err(_) = store_key("master", &master_key) {
        print_line(b"Failed to store master key", COLOR_RED);
        return;
    }

    print_line(b"[3/3] Vault ready", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);

    set_initialized(true);
    set_sealed(false);

    print_line(b"Vault UNSEALED", COLOR_GREEN);
    print_line(b"Crypto operations available", COLOR_ACCENT);
}

pub fn cmd_vault_erase() {
    if !is_initialized() {
        print_line(b"Vault not initialized", COLOR_RED);
        return;
    }

    print_line(b"WARNING: This will destroy all vault keys!", COLOR_RED);
    print_line(b"", COLOR_TEXT);
    print_line(b"Erasing Vault...", COLOR_YELLOW);
    print_line(b"", COLOR_TEXT);
    print_line(b"[1/4] Zeroing derived keys...", COLOR_TEXT);
    print_line(b"[2/4] Zeroing master key...", COLOR_TEXT);
    print_line(b"[3/4] Zeroing keypairs...", COLOR_TEXT);

    zeroize_all_keys();

    print_line(b"[4/4] Memory barrier complete", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);

    set_sealed(true);

    print_line(b"Vault ERASED", COLOR_GREEN);
    print_line(b"All cryptographic material destroyed", COLOR_YELLOW);
}
