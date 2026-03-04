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

use super::state::*;

pub(super) fn handle_locked_click(x: u32, y: u32, w: u32, h: u32) -> bool {
    let center_x: u32 = w / 2;
    let center_y: u32 = h / 2;

    let field_x1 = center_x.saturating_sub(120);
    let field_x2 = center_x + 120;
    let field_y1 = center_y + 5;
    let field_y2 = center_y + 33;

    if x >= field_x1 && x <= field_x2 && y >= field_y1 && y <= field_y2 {
        PASSWORD_FOCUSED.store(true, Ordering::SeqCst);
        return true;
    }

    let btn_x1 = center_x.saturating_sub(60);
    let btn_x2 = center_x + 60;
    let btn_y1 = center_y + 50;
    let btn_y2 = center_y + 82;

    if x >= btn_x1 && x <= btn_x2 && y >= btn_y1 && y <= btn_y2 {
        try_unlock();
        return true;
    }

    PASSWORD_FOCUSED.store(false, Ordering::SeqCst);
    false
}

pub(super) fn try_unlock() {
    use crate::crypto::blake3_hash;

    let pwd = PASSWORD_INPUT.lock();
    let pwd_len = PASSWORD_LEN.load(Ordering::SeqCst);

    if pwd_len == 0 {
        set_status(b"Enter a master key", false);
        return;
    }

    let master_key = blake3_hash(&pwd[..pwd_len]);
    drop(pwd);

    match init_wallet(master_key) {
        Ok(()) => {
            let mut pwd = PASSWORD_INPUT.lock();
            for b in pwd.iter_mut() { *b = 0; }
            PASSWORD_LEN.store(0, Ordering::SeqCst);
            PASSWORD_FOCUSED.store(false, Ordering::SeqCst);
        }
        Err(e) => {
            set_status(e.as_bytes(), false);
        }
    }
}
