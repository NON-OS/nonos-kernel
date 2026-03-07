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

/*
 * Handles clicks on the locked wallet screen. Returns true if the click
 * was handled, false if it fell outside all interactive regions.
 *
 * The layout has three interactive regions stacked vertically:
 * 1. Password input field (240px wide, centered)
 * 2. Unlock button (120px wide, centered, below password)
 * 3. New Wallet button (120px wide, centered, below unlock)
 */
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

    let new_btn_x1 = center_x.saturating_sub(60);
    let new_btn_x2 = center_x + 60;
    let new_btn_y1 = center_y + 90;
    let new_btn_y2 = center_y + 118;

    if x >= new_btn_x1 && x <= new_btn_x2 && y >= new_btn_y1 && y <= new_btn_y2 {
        generate_new_wallet();
        return true;
    }

    PASSWORD_FOCUSED.store(false, Ordering::SeqCst);
    false
}

/*
 * Generates a brand new wallet with fresh cryptographic key material.
 *
 * Uses generate_secure_key() which collects 168 bytes of entropy from
 * 12 different sources (TSC readings, TSC jitter, PIT counter samples,
 * RTC timestamp, stack pointer, buffer addresses, ChaCha20 RNG pulls,
 * and a global counter) then mixes through BLAKE3 for a uniform 32-byte
 * master key. This ensures unique wallets even on deterministic systems.
 */
fn generate_new_wallet() {
    use crate::crypto::generate_secure_key;

    lock_wallet();

    let master_key = generate_secure_key();

    match init_wallet(master_key) {
        Ok(()) => {
            let mut pwd = PASSWORD_INPUT.lock();
            for b in pwd.iter_mut() {
                *b = 0;
            }
            PASSWORD_LEN.store(0, Ordering::SeqCst);
            PASSWORD_FOCUSED.store(false, Ordering::SeqCst);
            set_status(b"New wallet created", true);
        }
        Err(e) => {
            set_status(e.as_bytes(), false);
        }
    }
}

/*
 * Attempts to unlock an existing wallet using the entered password.
 *
 * The password is hashed with BLAKE3 to derive the master key. This allows
 * users to restore their wallet on any device by entering the same password.
 * Unlike generate_new_wallet(), this is deterministic by design since the
 * same password must produce the same wallet across devices.
 */
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
