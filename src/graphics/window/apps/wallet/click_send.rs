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

pub(super) fn handle_send_click(x: u32, y: u32, w: u32) -> bool {
    if y >= 40 && y <= 118 && x >= 16 && x <= w - 52 {
        SEND_FIELD.store(0, Ordering::SeqCst);
        INPUT_FOCUSED.store(true, Ordering::SeqCst);
        INPUT_CURSOR.store(SEND_ADDRESS_LEN.load(Ordering::SeqCst), Ordering::SeqCst);
        return true;
    }

    if y >= 100 && y <= 178 && x >= 16 && x <= w - 52 {
        SEND_FIELD.store(1, Ordering::SeqCst);
        INPUT_FOCUSED.store(true, Ordering::SeqCst);
        INPUT_CURSOR.store(SEND_AMOUNT_LEN.load(Ordering::SeqCst), Ordering::SeqCst);
        return true;
    }

    if y >= 180 && y <= 216 && x >= w / 2 - 60 && x <= w / 2 + 60 {
        super::transaction::execute_send();
        return true;
    }

    INPUT_FOCUSED.store(false, Ordering::SeqCst);
    false
}

pub(super) fn handle_stealth_click(x: u32, y: u32, w: u32, h: u32) -> bool {
    let half_btn_w = (w - 50) / 2;

    if y >= 230 && y <= 266 {
        if x >= 20 && x <= 20 + half_btn_w {
            generate_stealth_receive_address();
            return true;
        }
        if x >= 30 + half_btn_w && x <= 30 + 2 * half_btn_w {
            initialize_zk_proofs();
            return true;
        }
    }

    if h > 450 {
        let proof_btn_y = h - 155;
        if y >= proof_btn_y && y <= proof_btn_y + 30 && x >= w - 160 && x <= w - 40 {
            generate_zk_proof_for_balance();
            return true;
        }
    }

    false
}

fn initialize_zk_proofs() {
    match super::zk::init_wallet_zk() {
        Ok(()) => {
            set_status(b"ZK Engine initialized", true);
        }
        Err(_) => {
            set_status(b"ZK init failed", false);
        }
    }
}

fn generate_zk_proof_for_balance() {
    use super::zk;

    if !zk::is_zk_available() {
        match zk::init_wallet_zk() {
            Ok(()) => {}
            Err(_) => {
                set_status(b"ZK not available", false);
                return;
            }
        }
    }

    let state = WALLET_STATE.lock();
    if !state.unlocked {
        drop(state);
        set_status(b"Wallet locked", false);
        return;
    }

    let (balance, secret_key, address) = match state.get_active_account() {
        Some(acc) => (acc.balance, acc.secret_key, acc.address),
        None => {
            drop(state);
            set_status(b"No active account", false);
            return;
        }
    };
    drop(state);

    match zk::prove_balance_ownership(balance, &secret_key, &address) {
        Ok(proof) => {
            let proof_bytes = proof.to_bytes();
            let mut status = [0u8; 64];
            let msg = b"ZK Proof generated: ";
            status[..msg.len()].copy_from_slice(msg);

            let size = proof_bytes.len();
            let mut idx = msg.len();
            if size >= 100 {
                status[idx] = b'0' + ((size / 100) % 10) as u8;
                idx += 1;
            }
            if size >= 10 {
                status[idx] = b'0' + ((size / 10) % 10) as u8;
                idx += 1;
            }
            status[idx] = b'0' + (size % 10) as u8;
            idx += 1;
            status[idx..idx + 6].copy_from_slice(b" bytes");

            set_status(&status[..idx + 6], true);
        }
        Err(_) => {
            set_status(b"Proof generation failed", false);
        }
    }
}

fn generate_stealth_receive_address() {
    use super::zk::{prove_stealth_spend_key, verify_wallet_proof};
    use super::zk_helpers::generate_blinding_factor;

    let state = WALLET_STATE.lock();
    if let Some(ref keypair) = state.stealth_keypair {
        let meta = keypair.meta_address();
        let encoded = meta.encode();
        if encoded.len() > 0 {
            let spend_secret = keypair.spend_secret;
            let view_secret = keypair.view_secret;
            let ephemeral_secret = generate_blinding_factor();
            let stealth_addr = keypair.derive_stealth_address(&ephemeral_secret);
            drop(state);

            if let Ok(proof) = prove_stealth_spend_key(
                &spend_secret,
                &view_secret,
                &ephemeral_secret,
                &stealth_addr,
            ) {
                match verify_wallet_proof(&proof) {
                    Ok(true) => {
                        set_status(b"Stealth address generated with proof", true);
                    }
                    Ok(false) => {
                        set_status(b"Stealth proof verification failed", false);
                    }
                    Err(_) => {
                        set_status(b"Stealth address generated", true);
                    }
                }
            } else {
                set_status(b"Stealth address generated", true);
            }
        } else {
            drop(state);
            set_status(b"Failed to encode stealth address", false);
        }
    } else {
        drop(state);
        set_status(b"Stealth keys not available", false);
    }
}

pub(super) fn handle_settings_click(x: u32, y: u32, w: u32) -> bool {
    let h = 400;

    let export_y = 50 + 3 * 60;
    if x >= 20 && x <= w - 20 && y >= export_y && y <= export_y + 70 {
        let current = SHOW_PRIVATE_KEY.load(Ordering::Relaxed);
        SHOW_PRIVATE_KEY.store(!current, Ordering::Relaxed);
        return true;
    }

    if y >= h - 130 && y <= h - 90 && x >= 20 && x <= w - 20 {
        SHOW_PRIVATE_KEY.store(false, Ordering::Relaxed);
        lock_wallet();
        set_view(WalletView::Overview);
        return true;
    }
    false
}
