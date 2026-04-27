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
use crate::crypto::{blake3_derive_key, blake3_hash, generate_secure_key};
use core::sync::atomic::{AtomicU64, Ordering};

static WALLET_GEN_CTR: AtomicU64 = AtomicU64::new(0x4E4F4E4F_57414C54);

pub(super) fn handle_locked_click(x: u32, y: u32, w: u32, h: u32) -> bool {
    let (cx, cy) = (w / 2, h / 2);
    if x >= cx.saturating_sub(130) && x <= cx + 130 && y >= cy && y <= cy + 32 {
        PASSWORD_FOCUSED.store(true, Ordering::SeqCst);
        return true;
    }
    if x >= cx.saturating_sub(130) && x <= cx.saturating_sub(5) && y >= cy + 55 && y <= cy + 99 {
        try_unlock();
        return true;
    }
    if x >= cx + 5 && x <= cx + 130 && y >= cy + 55 && y <= cy + 99 {
        generate_new_wallet();
        return true;
    }
    PASSWORD_FOCUSED.store(false, Ordering::SeqCst);
    false
}

fn generate_new_wallet() {
    lock_wallet();
    let pwd = PASSWORD_INPUT.lock();
    let pwd_len = PASSWORD_LEN.load(Ordering::SeqCst).min(63);
    let hw = generate_secure_key();
    let ts = crate::time::now_ns();
    let ctr = WALLET_GEN_CTR.fetch_add(0xA3B7C1D5E9F24680, Ordering::SeqCst);
    let mut combined = [0u8; 80];
    combined[0..32].copy_from_slice(&hw);
    if pwd_len > 0 {
        combined[32..32 + pwd_len.min(32)].copy_from_slice(&pwd[..pwd_len.min(32)]);
    }
    combined[64..72].copy_from_slice(&ts.to_le_bytes());
    combined[72..80].copy_from_slice(&ctr.to_le_bytes());
    let mut key = [0u8; 32];
    blake3_derive_key("NONOS:WALLET:NEW:v2", &combined, &mut key);
    for b in combined.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    drop(pwd);
    match init_wallet(key) {
        Ok(()) => {
            clear_pwd();
            set_status(
                if pwd_len > 0 { b"Wallet created with password" } else { b"New wallet created" },
                true,
            );
        }
        Err(e) => {
            set_status(e.as_bytes(), false);
        }
    }
}

pub(super) fn try_unlock() {
    let pwd = PASSWORD_INPUT.lock();
    let len = PASSWORD_LEN.load(Ordering::SeqCst).min(63);
    if len == 0 {
        set_status(b"Enter a master key", false);
        return;
    }
    let key = blake3_hash(&pwd[..len]);
    drop(pwd);
    match init_wallet(key) {
        Ok(()) => {
            clear_pwd();
        }
        Err(e) => {
            set_status(e.as_bytes(), false);
        }
    }
}

fn clear_pwd() {
    let mut pwd = PASSWORD_INPUT.lock();
    for b in pwd.iter_mut() {
        *b = 0;
    }
    PASSWORD_LEN.store(0, Ordering::SeqCst);
    PASSWORD_FOCUSED.store(false, Ordering::SeqCst);
}
