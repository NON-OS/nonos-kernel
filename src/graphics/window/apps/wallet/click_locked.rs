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

/*
 * Wallet locked screen click handlers.
 *
 * This module handles user interactions on the wallet's locked/login screen:
 * - Password field focus on click
 * - Unlock button to derive wallet from password
 * - New Wallet button to generate fresh cryptographic key material
 *
 * The "New Wallet" flow uses aggressive entropy collection from 12+ sources
 * to ensure unique keys even across VM reboots or shortly after boot when
 * the system RNG may be in a predictable state. This addresses GitHub #10
 * where identical wallets were generated due to insufficient entropy.
 */

use core::sync::atomic::Ordering;

use super::state::*;

pub(super) fn handle_locked_click(x: u32, y: u32, w: u32, h: u32) -> bool {
    let center_x: u32 = w / 2;
    let center_y: u32 = h / 2;

    let field_x1 = center_x.saturating_sub(130);
    let field_x2 = center_x + 130;
    let field_y1 = center_y;
    let field_y2 = center_y + 32;

    if x >= field_x1 && x <= field_x2 && y >= field_y1 && y <= field_y2 {
        PASSWORD_FOCUSED.store(true, Ordering::SeqCst);
        return true;
    }

    let unlock_x1 = center_x.saturating_sub(130);
    let unlock_x2 = center_x.saturating_sub(5);
    let unlock_y1 = center_y + 55;
    let unlock_y2 = center_y + 99;

    if x >= unlock_x1 && x <= unlock_x2 && y >= unlock_y1 && y <= unlock_y2 {
        try_unlock();
        return true;
    }

    let new_btn_x1 = center_x + 5;
    let new_btn_x2 = center_x + 130;
    let new_btn_y1 = center_y + 55;
    let new_btn_y2 = center_y + 99;

    if x >= new_btn_x1 && x <= new_btn_x2 && y >= new_btn_y1 && y <= new_btn_y2 {
        generate_new_wallet();
        return true;
    }

    PASSWORD_FOCUSED.store(false, Ordering::SeqCst);
    false
}

fn generate_new_wallet() {
    use crate::crypto::{generate_secure_key, blake3_derive_key};
    use core::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    static WALLET_GEN_COUNTER: AtomicU64 = AtomicU64::new(0x4E4F4E4F_57414C54);

    lock_wallet();

    let pwd = PASSWORD_INPUT.lock();
    let pwd_len = PASSWORD_LEN.load(Ordering::SeqCst);

    let hw_entropy = generate_secure_key();
    let click_time = crate::time::now_ns();
    let counter = WALLET_GEN_COUNTER.fetch_add(0xA3B7C1D5E9F24680, AtomicOrdering::SeqCst);

    let mut combined = [0u8; 80];
    combined[0..32].copy_from_slice(&hw_entropy);

    if pwd_len > 0 {
        combined[32..32 + pwd_len.min(32)].copy_from_slice(&pwd[..pwd_len.min(32)]);
    }

    combined[64..72].copy_from_slice(&click_time.to_le_bytes());
    combined[72..80].copy_from_slice(&counter.to_le_bytes());

    let mut master_key = [0u8; 32];
    blake3_derive_key("NONOS:WALLET:NEW:v2", &combined, &mut master_key);

    for b in combined.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }

    drop(pwd);

    match init_wallet(master_key) {
        Ok(()) => {
            let mut pwd = PASSWORD_INPUT.lock();
            for b in pwd.iter_mut() {
                *b = 0;
            }
            PASSWORD_LEN.store(0, Ordering::SeqCst);
            PASSWORD_FOCUSED.store(false, Ordering::SeqCst);
            if pwd_len > 0 {
                set_status(b"Wallet created with password", true);
            } else {
                set_status(b"New wallet created", true);
            }
        }
        Err(e) => {
            set_status(e.as_bytes(), false);
        }
    }
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
            for b in pwd.iter_mut() {
                *b = 0;
            }
            PASSWORD_LEN.store(0, Ordering::SeqCst);
            PASSWORD_FOCUSED.store(false, Ordering::SeqCst);
        }
        Err(e) => {
            set_status(e.as_bytes(), false);
        }
    }
}
