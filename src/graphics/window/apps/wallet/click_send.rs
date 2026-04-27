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
use super::zk::{
    init_wallet_zk, is_zk_available, prove_balance_ownership, prove_stealth_spend_key,
    verify_wallet_proof,
};
use super::zk_helpers::generate_blinding_factor;
use core::sync::atomic::Ordering;

pub(super) fn handle_send_click(x: u32, y: u32, w: u32) -> bool {
    if y >= 90 && y <= 122 && x >= 36 && x <= w - 36 {
        SEND_FIELD.store(0, Ordering::SeqCst);
        INPUT_FOCUSED.store(true, Ordering::SeqCst);
        INPUT_CURSOR.store(SEND_ADDRESS_LEN.load(Ordering::SeqCst), Ordering::SeqCst);
        return true;
    }
    if y >= 155 && y <= 187 && x >= 36 && x <= w - 84 {
        SEND_FIELD.store(1, Ordering::SeqCst);
        INPUT_FOCUSED.store(true, Ordering::SeqCst);
        INPUT_CURSOR.store(SEND_AMOUNT_LEN.load(Ordering::SeqCst), Ordering::SeqCst);
        return true;
    }
    if y >= 155 && y <= 187 && x >= w - 80 && x <= w - 36 {
        SEND_TOKEN_TYPE.store(
            if SEND_TOKEN_TYPE.load(Ordering::SeqCst) == 0 { 1 } else { 0 },
            Ordering::SeqCst,
        );
        return true;
    }
    if y >= 295 && y <= 335 && x >= w / 2 - 65 && x <= w / 2 + 65 {
        super::transaction::execute_token_send();
        return true;
    }
    INPUT_FOCUSED.store(false, Ordering::SeqCst);
    false
}

pub(super) fn handle_stealth_click(x: u32, y: u32, w: u32, h: u32) -> bool {
    let hbw = (w - 50) / 2;
    if y >= 230 && y <= 266 {
        if x >= 20 && x <= 20 + hbw {
            gen_stealth();
            return true;
        }
        if x >= 30 + hbw && x <= 30 + 2 * hbw {
            match init_wallet_zk() {
                Ok(()) => set_status(b"ZK Engine initialized", true),
                Err(_) => set_status(b"ZK init failed", false),
            }
            return true;
        }
    }
    if h > 450 && y >= h - 155 && y <= h - 125 && x >= w - 160 && x <= w - 40 {
        gen_zk_proof();
        return true;
    }
    false
}

fn gen_zk_proof() {
    if !is_zk_available() {
        if init_wallet_zk().is_err() {
            set_status(b"ZK not available", false);
            return;
        }
    }
    let s = WALLET_STATE.lock();
    if !s.unlocked {
        drop(s);
        set_status(b"Wallet locked", false);
        return;
    }
    let (bal, sk, addr) = match s.get_active_account() {
        Some(a) => (a.balance, a.secret_key, a.address),
        None => {
            drop(s);
            set_status(b"No active account", false);
            return;
        }
    };
    drop(s);
    match prove_balance_ownership(bal, &sk, &addr) {
        Ok(p) => {
            let sz = p.to_bytes().len();
            let mut st = [0u8; 40];
            st[..20].copy_from_slice(b"ZK Proof generated: ");
            let mut i = 20;
            if sz >= 100 {
                st[i] = b'0' + ((sz / 100) % 10) as u8;
                i += 1;
            }
            if sz >= 10 {
                st[i] = b'0' + ((sz / 10) % 10) as u8;
                i += 1;
            }
            st[i] = b'0' + (sz % 10) as u8;
            i += 1;
            st[i..i + 6].copy_from_slice(b" bytes");
            set_status(&st[..i + 6], true);
        }
        Err(_) => set_status(b"Proof generation failed", false),
    }
}

fn gen_stealth() {
    let s = WALLET_STATE.lock();
    if let Some(ref kp) = s.stealth_keypair {
        let meta = kp.meta_address();
        if meta.encode().len() > 0 {
            let (sp, vw, eph) = (kp.spend_secret, kp.view_secret, generate_blinding_factor());
            let sa = kp.derive_stealth_address(&eph);
            drop(s);
            if let Ok(pf) = prove_stealth_spend_key(&sp, &vw, &eph, &sa) {
                match verify_wallet_proof(&pf) {
                    Ok(true) => set_status(b"Stealth address generated with proof", true),
                    Ok(false) => set_status(b"Stealth proof verification failed", false),
                    Err(_) => set_status(b"Stealth address generated", true),
                }
            } else {
                set_status(b"Stealth address generated", true);
            }
        } else {
            drop(s);
            set_status(b"Failed to encode stealth address", false);
        }
    } else {
        drop(s);
        set_status(b"Stealth keys not available", false);
    }
}

pub(super) fn handle_settings_click(x: u32, y: u32, w: u32, h: u32) -> bool {
    if x >= 20 && x <= w - 20 && y <= 100 {
        super::network::toggle_network();
        set_status(b"Network switched - refresh balances", true);
        return true;
    }
    if x >= 20 && x <= w - 20 && y >= 185 && y <= 255 {
        SHOW_PRIVATE_KEY.store(!SHOW_PRIVATE_KEY.load(Ordering::Relaxed), Ordering::Relaxed);
        return true;
    }
    if y >= h - 80 && y <= h - 40 && x >= 20 && x <= w - 20 {
        SHOW_PRIVATE_KEY.store(false, Ordering::Relaxed);
        lock_wallet();
        set_view(WalletView::Overview);
        return true;
    }
    false
}
