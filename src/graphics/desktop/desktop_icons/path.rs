// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::state::{init_path, refresh, CURRENT_PATH, CURRENT_PATH_LEN, MAX_PATH};
use core::sync::atomic::Ordering;

pub(crate) fn navigate_into(name: &str) -> bool {
    init_path();
    let cur_len = CURRENT_PATH_LEN.load(Ordering::SeqCst) as usize;
    let name_len = name.len();
    if cur_len + 1 + name_len >= MAX_PATH {
        return false;
    }
    unsafe {
        CURRENT_PATH[cur_len] = b'/';
        CURRENT_PATH[cur_len + 1..cur_len + 1 + name_len].copy_from_slice(name.as_bytes());
        CURRENT_PATH_LEN.store((cur_len + 1 + name_len) as u8, Ordering::SeqCst);
    }
    refresh();
    true
}

pub(crate) fn navigate_back() -> bool {
    init_path();
    let len = CURRENT_PATH_LEN.load(Ordering::SeqCst) as usize;
    if len <= 4 {
        return false;
    }
    unsafe {
        for i in (4..len).rev() {
            if CURRENT_PATH[i] == b'/' {
                CURRENT_PATH_LEN.store(i as u8, Ordering::SeqCst);
                for j in i..MAX_PATH {
                    CURRENT_PATH[j] = 0;
                }
                break;
            }
        }
    }
    refresh();
    true
}
