// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use uefi::cstr16;
use uefi::prelude::*;

pub fn output_status(st: &mut SystemTable<Boot>, name: &str, ok: bool) {
    let msg = match (name, ok) {
        ("Production Keys", true) => cstr16!("Production Keys: LOADED\r\n"),
        ("Production Keys", false) => cstr16!("Production Keys: FAILED!\r\n"),
        ("SecureBoot", true) => cstr16!("SecureBoot: ENABLED\r\n"),
        ("SecureBoot", false) => cstr16!("SecureBoot: DISABLED\r\n"),
        ("PlatformKey", true) => cstr16!("PlatformKey: OK\r\n"),
        ("PlatformKey", false) => cstr16!("PlatformKey: MISSING\r\n"),
        ("SignatureDB", true) => cstr16!("SignatureDB: OK\r\n"),
        ("SignatureDB", false) => cstr16!("SignatureDB: MISSING\r\n"),
        ("HW RNG", true) => cstr16!("HW RNG: AVAILABLE\r\n"),
        ("HW RNG", false) => cstr16!("HW RNG: MISSING\r\n"),
        ("Measured Boot", true) => cstr16!("Measured Boot: ACTIVE\r\n"),
        ("Measured Boot", false) => cstr16!("Measured Boot: INACTIVE\r\n"),
        ("Ed25519", true) => cstr16!("Ed25519: PASS\r\n"),
        ("Ed25519", false) => cstr16!("Ed25519: FAIL\r\n"),
        ("BLAKE3", true) => cstr16!("BLAKE3: PASS\r\n"),
        ("BLAKE3", false) => cstr16!("BLAKE3: FAIL\r\n"),
        (_, true) => cstr16!("Unknown: OK\r\n"),
        (_, false) => cstr16!("Unknown: FAIL\r\n"),
    };
    let _ = st.stdout().output_string(msg);
}
