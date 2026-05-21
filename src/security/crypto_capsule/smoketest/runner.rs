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

use super::log::{fail, fail_msg, mark};
use super::vectors::*;
use crate::security::crypto_capsule::{client, state};

pub fn run() {
    if !state::is_alive() {
        return fail_msg(b"capsule not alive");
    }
    match client::hash_blake3(INPUT_ABC) {
        Ok(d) if d == KAT_BLAKE3_ABC => mark(b"blake3 ok"),
        Ok(_) => return fail_msg(b"blake3: digest mismatch"),
        Err(e) => return fail(b"blake3", e),
    }
    match client::hash_sha3_256(INPUT_ABC) {
        Ok(d) if d == KAT_SHA3_256_ABC => mark(b"sha3 ok"),
        Ok(_) => return fail_msg(b"sha3: digest mismatch"),
        Err(e) => return fail(b"sha3", e),
    }
    match client::hash_sha256(INPUT_ABC) {
        Ok(d) if d == KAT_SHA256_ABC => mark(b"sha256 ok"),
        Ok(_) => return fail_msg(b"sha256: digest mismatch"),
        Err(e) => return fail(b"sha256", e),
    }
    match client::hash_sha512(INPUT_ABC) {
        Ok(d) if d == KAT_SHA512_ABC => mark(b"sha512 ok"),
        Ok(_) => return fail_msg(b"sha512: digest mismatch"),
        Err(e) => return fail(b"sha512", e),
    }
    mark(b"PASS");
}
