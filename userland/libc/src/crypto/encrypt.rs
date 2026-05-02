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

use crate::syscall::{call_raw, N_CRYPTO_ENCRYPT};

// `algo` selects the AEAD: 0 = ChaCha20-Poly1305, 1 = AES-256-GCM. The
// kernel handler reads exactly 32 bytes at `key` and 12 bytes at
// `nonce`, encrypts `plaintext_len` bytes, and writes
// `plaintext_len + 16` bytes to `ciphertext`. Returns the ciphertext
// length on success or the negated kernel errno on failure.
#[no_mangle]
pub extern "C" fn crypto_encrypt(
    algo: u64,
    key: *const u8,
    nonce: *const u8,
    plaintext: *const u8,
    plaintext_len: u64,
    ciphertext: *mut u8,
) -> i64 {
    call_raw(
        N_CRYPTO_ENCRYPT,
        [algo, key as u64, nonce as u64, plaintext as u64, plaintext_len, ciphertext as u64],
    )
}
