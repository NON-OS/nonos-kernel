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

use super::constants::SECP256K1_ORDER;

pub(crate) fn is_valid_secret_key(key: &[u8; 32]) -> bool {
    let all_zero = key.iter().all(|&b| b == 0);
    if all_zero {
        return false;
    }

    for i in 0..32 {
        if key[i] < SECP256K1_ORDER[i] {
            return true;
        }
        if key[i] > SECP256K1_ORDER[i] {
            return false;
        }
    }

    false
}

pub(crate) fn is_valid_tweak(tweak: &[u8; 32]) -> bool {
    for i in 0..32 {
        if tweak[i] < SECP256K1_ORDER[i] {
            return true;
        }
        if tweak[i] > SECP256K1_ORDER[i] {
            return false;
        }
    }
    false
}
