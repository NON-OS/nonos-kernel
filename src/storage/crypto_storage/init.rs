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

use alloc::vec;
use crate::crypto::{secure_random_u32, aes256_gcm_encrypt};

pub fn init() -> Result<(), &'static str> {
    let entropy_test = secure_random_u32();
    if entropy_test == 0 {
        return Err("Cryptographic entropy source failure during storage initialization");
    }

    let test_key = [0u8; 32];
    let test_data = vec![0xde, 0xad, 0xbe, 0xef];
    let test_nonce = [0u8; 12];
    let test_aad = &[];

    match aes256_gcm_encrypt(&test_key, &test_nonce, &test_data, test_aad) {
        Ok(_) => {
            crate::log::log(crate::log::Severity::Info, "Cryptographic storage subsystem initialized with verified AES-256-GCM capability");
            Ok(())
        },
        Err(_) => Err("Cryptographic storage initialization failed during AES-256-GCM verification")
    }
}
