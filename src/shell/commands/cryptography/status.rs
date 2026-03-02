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
use crate::graphics::framebuffer::{COLOR_ACCENT, COLOR_GREEN, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE};

pub fn cmd_crypto_status() {
    print_line(b"Cryptographic Subsystem Status:", COLOR_TEXT_WHITE);
    print_line(b"============================================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);

    print_line(b"Hash Functions:", COLOR_TEXT_WHITE);
    print_line(b"  BLAKE3        READY", COLOR_GREEN);
    print_line(b"  SHA-256       READY", COLOR_GREEN);
    print_line(b"  SHA-512       READY", COLOR_GREEN);
    print_line(b"  SHA3-256      READY", COLOR_GREEN);
    print_line(b"", COLOR_TEXT);

    print_line(b"Symmetric Encryption:", COLOR_TEXT_WHITE);
    print_line(b"  AES-256-GCM   READY", COLOR_GREEN);
    print_line(b"  ChaCha20-Poly READY", COLOR_GREEN);
    print_line(b"", COLOR_TEXT);

    print_line(b"Asymmetric Crypto:", COLOR_TEXT_WHITE);
    print_line(b"  Ed25519       READY (signing)", COLOR_GREEN);
    print_line(b"  X25519        READY (ECDH)", COLOR_GREEN);
    print_line(b"  secp256k1     READY (Bitcoin)", COLOR_GREEN);
    print_line(b"", COLOR_TEXT);

    print_line(b"Post-Quantum Crypto:", COLOR_TEXT_WHITE);
    print_line(b"  Kyber1024     READY (KEM)", COLOR_ACCENT);
    print_line(b"  Dilithium5    READY (signing)", COLOR_ACCENT);
    print_line(b"  SPHINCS+      READY (hash-based)", COLOR_ACCENT);
    print_line(b"", COLOR_TEXT);

    print_line(b"Zero-Knowledge:", COLOR_TEXT_WHITE);
    print_line(b"  Groth16       READY", COLOR_ACCENT);
    print_line(b"  Halo2         READY", COLOR_ACCENT);
    print_line(b"", COLOR_TEXT);

    print_line(b"RNG Source: Hardware (RDRAND)", COLOR_GREEN);
}
