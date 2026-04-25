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

use super::capsule::TREASURY;
use crate::graphics::window::apps::wallet::{send_nox_to, WALLET_STATE};
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

static PAYMENT_PENDING: AtomicBool = AtomicBool::new(false);
static PAYMENT_APP_IDX: AtomicU8 = AtomicU8::new(0);
static PAYMENT_FEE: AtomicU8 = AtomicU8::new(0);

pub(super) fn initiate_payment(app_idx: usize, fee_nox: u32) -> bool {
    let s = WALLET_STATE.lock();
    if !s.unlocked {
        crate::graphics::window::notify_error(b"Unlock wallet first");
        return false;
    }
    let fee_wei = (fee_nox as u128) * 1_000_000_000_000_000_000;
    if s.total_nox_balance() < fee_wei {
        crate::graphics::window::notify_error(b"Insufficient NOX");
        return false;
    }
    drop(s);
    PAYMENT_APP_IDX.store(app_idx as u8, Ordering::Relaxed);
    PAYMENT_FEE.store(fee_nox as u8, Ordering::Relaxed);
    PAYMENT_PENDING.store(true, Ordering::Relaxed);
    true
}

pub(super) fn execute_pending_payment() -> bool {
    if !PAYMENT_PENDING.load(Ordering::Relaxed) {
        return false;
    }
    let app_idx = PAYMENT_APP_IDX.load(Ordering::Relaxed) as usize;
    let fee = PAYMENT_FEE.load(Ordering::Relaxed) as u32;
    let fee_wei = (fee as u128) * 1_000_000_000_000_000_000;
    PAYMENT_PENDING.store(false, Ordering::Relaxed);
    match send_nox_to(&TREASURY, fee_wei) {
        Ok(_) => {
            let capsule_id = [0u8; 32]; // Placeholder until we get real ID
            super::capsule::create_capsule(app_idx, &capsule_id, "installed_app", 0);
            crate::graphics::window::notify_success(b"App installed!");
            true
        }
        Err(e) => {
            crate::graphics::window::notify_error(e);
            false
        }
    }
}
