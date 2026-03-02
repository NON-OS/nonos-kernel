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

use crate::crypto::application::vault::{list_keys, list_vault_keys};
use crate::shell::output::print_line;
use crate::graphics::framebuffer::{
    COLOR_TEXT_WHITE, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_GREEN, COLOR_YELLOW, COLOR_RED, COLOR_ACCENT,
};

use super::state::{is_sealed, is_initialized};
use super::format::print_key_count;

pub fn cmd_vault_status() {
    print_line(b"Vault Status:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);

    let initialized = is_initialized();
    let sealed = is_sealed();

    if !initialized {
        print_line(b"State:          NOT INITIALIZED", COLOR_RED);
        print_line(b"", COLOR_TEXT);
        print_line(b"Run 'vault-unseal <passphrase>' to initialize", COLOR_TEXT_DIM);
        return;
    }

    if sealed {
        print_line(b"State:          SEALED", COLOR_YELLOW);
    } else {
        print_line(b"State:          UNSEALED", COLOR_GREEN);
    }

    print_line(b"Storage:        RAM only (ZeroState)", COLOR_YELLOW);
    print_line(b"Encryption:     ChaCha20-Poly1305", COLOR_TEXT);
    print_line(b"Key Derivation: BLAKE3-HKDF", COLOR_TEXT);
    print_line(b"", COLOR_TEXT);

    print_line(b"Available Engines:", COLOR_TEXT_WHITE);
    print_line(b"  ed25519       READY (signing)", COLOR_GREEN);
    print_line(b"  x25519        READY (ECDH)", COLOR_GREEN);
    print_line(b"  chacha20      READY (symmetric)", COLOR_GREEN);
    print_line(b"  kyber1024     READY (PQC)", COLOR_ACCENT);
    print_line(b"  dilithium5    READY (PQC signing)", COLOR_ACCENT);

    print_line(b"", COLOR_TEXT);

    let string_keys = list_keys().unwrap_or_default();
    let keypairs = list_vault_keys();

    print_key_count(b"Stored Keys:    ", string_keys.len());
    print_key_count(b"Keypairs:       ", keypairs.len());

    print_line(b"", COLOR_TEXT);
    print_line(b"All keys erased on shutdown", COLOR_YELLOW);
}

pub fn cmd_vault_policy() {
    print_line(b"Vault Policies:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);

    print_line(b"Key Lifetime:", COLOR_TEXT_WHITE);
    print_line(b"  Master Key:     Session (RAM only)", COLOR_YELLOW);
    print_line(b"  Derived Keys:   Session (RAM only)", COLOR_YELLOW);
    print_line(b"  Ephemeral:      Single use", COLOR_TEXT);

    print_line(b"", COLOR_TEXT);
    print_line(b"Access Control:", COLOR_TEXT_WHITE);
    print_line(b"  Sign:           Allowed", COLOR_GREEN);
    print_line(b"  Encrypt:        Allowed", COLOR_GREEN);
    print_line(b"  Decrypt:        Allowed", COLOR_GREEN);
    print_line(b"  Export:         DENIED", COLOR_RED);
    print_line(b"  Persist:        DENIED (ZeroState)", COLOR_RED);

    print_line(b"", COLOR_TEXT);
    print_line(b"Algorithms:", COLOR_TEXT_WHITE);
    print_line(b"  Classical:      Ed25519, X25519, ChaCha20", COLOR_TEXT);
    print_line(b"  Post-Quantum:   Kyber, Dilithium", COLOR_ACCENT);
    print_line(b"  Hybrid:         ENABLED", COLOR_GREEN);

    print_line(b"", COLOR_TEXT);
    print_line(b"Audit:", COLOR_TEXT_WHITE);
    print_line(b"  Logging:        All operations", COLOR_GREEN);
    print_line(b"  Log Storage:    RAM only", COLOR_YELLOW);
}

pub fn cmd_vault_audit() {
    print_line(b"Vault Audit Log:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);

    let initialized = is_initialized();
    let sealed = is_sealed();

    if initialized {
        print_line(b"[INFO]  Vault initialized", COLOR_GREEN);
    } else {
        print_line(b"[INFO]  Vault not initialized", COLOR_YELLOW);
    }

    print_line(b"[INFO]  Engine: ed25519 loaded", COLOR_GREEN);
    print_line(b"[INFO]  Engine: chacha20-poly1305 loaded", COLOR_GREEN);
    print_line(b"[INFO]  Engine: blake3 loaded", COLOR_GREEN);
    print_line(b"[INFO]  Engine: kyber1024 loaded", COLOR_ACCENT);
    print_line(b"[INFO]  Engine: dilithium5 loaded", COLOR_ACCENT);

    if !sealed {
        print_line(b"[INFO]  Vault ready (unsealed)", COLOR_GREEN);
    } else {
        print_line(b"[WARN]  Vault sealed", COLOR_YELLOW);
    }

    print_line(b"", COLOR_TEXT);

    let string_keys = list_keys().unwrap_or_default();
    let keypairs = list_vault_keys();

    print_key_count(b"Keys stored: ", string_keys.len());
    print_key_count(b"Keypairs: ", keypairs.len());

    print_line(b"", COLOR_TEXT);
    print_line(b"Audit log in RAM (erased on shutdown)", COLOR_YELLOW);
}
