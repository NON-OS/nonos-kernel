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
use crate::graphics::window::text_editor::SpecialKey;

use super::state::*;

pub(super) fn handle_key(ch: u8) {
    let state = WALLET_STATE.lock();
    let is_locked = !state.unlocked;
    drop(state);

    if is_locked {
        handle_locked_key(ch);
        return;
    }

    if !INPUT_FOCUSED.load(Ordering::SeqCst) {
        return;
    }

    let field = SEND_FIELD.load(Ordering::SeqCst);

    if field == 0 {
        handle_address_key(ch);
    } else {
        handle_amount_key(ch);
    }
}

pub(super) fn handle_locked_key(ch: u8) {
    if !PASSWORD_FOCUSED.load(Ordering::SeqCst) {
        return;
    }

    let mut pwd = PASSWORD_INPUT.lock();
    let len = PASSWORD_LEN.load(Ordering::SeqCst);

    if ch == 0x08 || ch == 0x7F {
        if len > 0 {
            pwd[len - 1] = 0;
            PASSWORD_LEN.store(len - 1, Ordering::SeqCst);
        }
        return;
    }

    if ch == 0x0D || ch == 0x0A {
        drop(pwd);
        super::click_locked::try_unlock();
        return;
    }

    if ch >= 0x20 && ch < 0x7F && len < 63 {
        pwd[len] = ch;
        PASSWORD_LEN.store(len + 1, Ordering::SeqCst);
    }
}

fn handle_address_key(ch: u8) {
    let mut buf = SEND_ADDRESS.lock();
    let len = SEND_ADDRESS_LEN.load(Ordering::SeqCst);
    let cursor = INPUT_CURSOR.load(Ordering::SeqCst).min(len);

    if ch == 0x08 || ch == 0x7F {
        if cursor > 0 {
            for i in cursor - 1..len.saturating_sub(1) {
                buf[i] = buf[i + 1];
            }
            SEND_ADDRESS_LEN.store(len.saturating_sub(1), Ordering::SeqCst);
            INPUT_CURSOR.store(cursor - 1, Ordering::SeqCst);
        }
        return;
    }

    let valid = (ch >= b'0' && ch <= b'9')
        || (ch >= b'a' && ch <= b'f')
        || (ch >= b'A' && ch <= b'F')
        || ch == b'x'
        || ch == b'X';

    if valid && len < 63 {
        for i in (cursor..len).rev() {
            buf[i + 1] = buf[i];
        }
        buf[cursor] = if ch >= b'A' && ch <= b'F' { ch + 32 } else { ch };
        SEND_ADDRESS_LEN.store(len + 1, Ordering::SeqCst);
        INPUT_CURSOR.store(cursor + 1, Ordering::SeqCst);
    }
}

fn handle_amount_key(ch: u8) {
    let mut buf = SEND_AMOUNT.lock();
    let len = SEND_AMOUNT_LEN.load(Ordering::SeqCst);
    let cursor = INPUT_CURSOR.load(Ordering::SeqCst).min(len);

    if ch == 0x08 || ch == 0x7F {
        if cursor > 0 {
            for i in cursor - 1..len.saturating_sub(1) {
                buf[i] = buf[i + 1];
            }
            SEND_AMOUNT_LEN.store(len.saturating_sub(1), Ordering::SeqCst);
            INPUT_CURSOR.store(cursor - 1, Ordering::SeqCst);
        }
        return;
    }

    let valid = (ch >= b'0' && ch <= b'9') || ch == b'.';

    if valid && len < 31 {
        if ch == b'.' {
            for i in 0..len {
                if buf[i] == b'.' {
                    return;
                }
            }
        }

        for i in (cursor..len).rev() {
            buf[i + 1] = buf[i];
        }
        buf[cursor] = ch;
        SEND_AMOUNT_LEN.store(len + 1, Ordering::SeqCst);
        INPUT_CURSOR.store(cursor + 1, Ordering::SeqCst);
    }
}

pub(super) fn handle_special_key(key: SpecialKey) {
    if !INPUT_FOCUSED.load(Ordering::SeqCst) {
        return;
    }

    let field = SEND_FIELD.load(Ordering::SeqCst);
    let len = if field == 0 {
        SEND_ADDRESS_LEN.load(Ordering::SeqCst)
    } else {
        SEND_AMOUNT_LEN.load(Ordering::SeqCst)
    };
    let cursor = INPUT_CURSOR.load(Ordering::SeqCst);

    match key {
        SpecialKey::Left => {
            if cursor > 0 {
                INPUT_CURSOR.store(cursor - 1, Ordering::SeqCst);
            }
        }
        SpecialKey::Right => {
            if cursor < len {
                INPUT_CURSOR.store(cursor + 1, Ordering::SeqCst);
            }
        }
        SpecialKey::Home => {
            INPUT_CURSOR.store(0, Ordering::SeqCst);
        }
        SpecialKey::End => {
            INPUT_CURSOR.store(len, Ordering::SeqCst);
        }
        _ => {}
    }
}
