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

use super::state::*;
use crate::graphics::window::text_editor::SpecialKey;
use core::sync::atomic::Ordering;

pub(super) fn handle_key(ch: u8) {
    let s = WALLET_STATE.lock();
    let locked = !s.unlocked;
    drop(s);
    if locked {
        handle_locked_key(ch);
        return;
    }
    let view = get_view();
    if view == WalletView::Staking {
        if ch == 0x08 || ch == 0x7F {
            super::staking::handle_staking_backspace();
        } else {
            super::staking::handle_staking_key(ch);
        }
        return;
    }
    if !INPUT_FOCUSED.load(Ordering::SeqCst) {
        return;
    }
    if SEND_FIELD.load(Ordering::SeqCst) == 0 {
        handle_addr_key(ch);
    } else {
        handle_amt_key(ch);
    }
}

pub(super) fn handle_locked_key(ch: u8) {
    if !PASSWORD_FOCUSED.load(Ordering::SeqCst) {
        return;
    }
    let mut p = PASSWORD_INPUT.lock();
    let len = PASSWORD_LEN.load(Ordering::SeqCst);
    if ch == 0x08 || ch == 0x7F {
        if len > 0 {
            p[len - 1] = 0;
            PASSWORD_LEN.store(len - 1, Ordering::SeqCst);
        }
        return;
    }
    if ch == 0x0D || ch == 0x0A {
        drop(p);
        super::click_locked::try_unlock();
        return;
    }
    if ch >= 0x20 && ch < 0x7F && len < 63 {
        p[len] = ch;
        PASSWORD_LEN.store(len + 1, Ordering::SeqCst);
    }
}

fn handle_addr_key(ch: u8) {
    let mut b = SEND_ADDRESS.lock();
    let (len, cur) = (
        SEND_ADDRESS_LEN.load(Ordering::SeqCst),
        INPUT_CURSOR.load(Ordering::SeqCst).min(SEND_ADDRESS_LEN.load(Ordering::SeqCst)),
    );
    if ch == 0x08 || ch == 0x7F {
        if cur > 0 {
            for i in cur - 1..len.saturating_sub(1) {
                b[i] = b[i + 1];
            }
            SEND_ADDRESS_LEN.store(len.saturating_sub(1), Ordering::SeqCst);
            INPUT_CURSOR.store(cur - 1, Ordering::SeqCst);
        }
        return;
    }
    let v = (ch >= b'0' && ch <= b'9')
        || (ch >= b'a' && ch <= b'f')
        || (ch >= b'A' && ch <= b'F')
        || ch == b'x'
        || ch == b'X';
    if v && len < 63 {
        for i in (cur..len).rev() {
            b[i + 1] = b[i];
        }
        b[cur] = if ch >= b'A' && ch <= b'F' { ch + 32 } else { ch };
        SEND_ADDRESS_LEN.store(len + 1, Ordering::SeqCst);
        INPUT_CURSOR.store(cur + 1, Ordering::SeqCst);
    }
}

fn handle_amt_key(ch: u8) {
    let mut b = SEND_AMOUNT.lock();
    let (len, cur) = (
        SEND_AMOUNT_LEN.load(Ordering::SeqCst),
        INPUT_CURSOR.load(Ordering::SeqCst).min(SEND_AMOUNT_LEN.load(Ordering::SeqCst)),
    );
    if ch == 0x08 || ch == 0x7F {
        if cur > 0 {
            for i in cur - 1..len.saturating_sub(1) {
                b[i] = b[i + 1];
            }
            SEND_AMOUNT_LEN.store(len.saturating_sub(1), Ordering::SeqCst);
            INPUT_CURSOR.store(cur - 1, Ordering::SeqCst);
        }
        return;
    }
    let v = (ch >= b'0' && ch <= b'9') || ch == b'.';
    if v && len < 31 {
        if ch == b'.' {
            for i in 0..len {
                if b[i] == b'.' {
                    return;
                }
            }
        }
        for i in (cur..len).rev() {
            b[i + 1] = b[i];
        }
        b[cur] = ch;
        SEND_AMOUNT_LEN.store(len + 1, Ordering::SeqCst);
        INPUT_CURSOR.store(cur + 1, Ordering::SeqCst);
    }
}

pub(super) fn handle_special_key(key: SpecialKey) {
    if !INPUT_FOCUSED.load(Ordering::SeqCst) {
        return;
    }
    let len = if SEND_FIELD.load(Ordering::SeqCst) == 0 {
        SEND_ADDRESS_LEN.load(Ordering::SeqCst)
    } else {
        SEND_AMOUNT_LEN.load(Ordering::SeqCst)
    };
    let cur = INPUT_CURSOR.load(Ordering::SeqCst);
    match key {
        SpecialKey::Left => {
            if cur > 0 {
                INPUT_CURSOR.store(cur - 1, Ordering::SeqCst);
            }
        }
        SpecialKey::Right => {
            if cur < len {
                INPUT_CURSOR.store(cur + 1, Ordering::SeqCst);
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
