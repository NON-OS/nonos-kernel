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

use uefi::prelude::*;
use uefi::proto::console::text::{Input, Key, ScanCode};

pub fn check_dev_key_held(bs: &BootServices) -> bool {
    let handle = match bs.get_handle_for_protocol::<Input>() {
        Ok(h) => h,
        Err(_) => return false,
    };

    let mut input = match bs.open_protocol_exclusive::<Input>(handle) {
        Ok(i) => i,
        Err(_) => return false,
    };

    for _ in 0..3 {
        bs.stall(50_000);
        if let Ok(Some(key)) = input.read_key() {
            if matches!(key, Key::Special(ScanCode::FUNCTION_12)) {
                return true;
            }
        }
    }

    false
}
