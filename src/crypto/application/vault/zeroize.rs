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

use core::sync::atomic::Ordering;
use super::string_vault::STRING_KEY_VAULT;
use super::key_vault::KEY_VAULT;

pub fn zeroize_all_keys() {
    {
        let mut string_vault = STRING_KEY_VAULT.write();
        for (_, key_data) in string_vault.iter_mut() {
            for byte in key_data.iter_mut() {
                unsafe { core::ptr::write_volatile(byte, 0) };
            }
        }
        string_vault.clear();
    }

    {
        let mut vault = KEY_VAULT.write();
        for (_, entry) in vault.iter_mut() {
            for byte in entry.private_key.iter_mut() {
                unsafe { core::ptr::write_volatile(byte, 0) };
            }
            for byte in entry.public_key.iter_mut() {
                unsafe { core::ptr::write_volatile(byte, 0) };
            }
        }
        vault.clear();
    }

    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}
