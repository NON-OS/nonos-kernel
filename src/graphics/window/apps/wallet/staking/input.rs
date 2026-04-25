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

use super::state::{clear_stake_input, STAKE_INPUT, STAKE_INPUT_LEN, STAKE_MODE};
use crate::graphics::window::apps::wallet::state::set_status;
use core::sync::atomic::Ordering;

pub(crate) fn handle_staking_click(x: u32, y: u32, w: u32) -> bool {
    if y >= 12 && y <= 40 && x >= w - 100 && x <= w - 24 {
        set_status(b"Refreshing...", true);
        super::state::refresh_staking_data();
        set_status(b"Staking data updated", true);
        return true;
    }
    if y >= 168 && y <= 198 {
        if x >= 40 && x <= 120 {
            STAKE_MODE.store(0, Ordering::SeqCst);
            clear_stake_input();
            return true;
        }
        if x >= 130 && x <= 210 {
            STAKE_MODE.store(1, Ordering::SeqCst);
            clear_stake_input();
            return true;
        }
    }
    if y >= 238 && y <= 272 && x >= w / 2 - 55 && x <= w / 2 + 55 {
        let mode = STAKE_MODE.load(Ordering::SeqCst);
        let len = STAKE_INPUT_LEN.load(Ordering::SeqCst) as usize;
        if len == 0 {
            set_status(b"Enter amount", false);
            return true;
        }
        let mut amount_buf = [0u8; 32];
        {
            let input = STAKE_INPUT.lock();
            amount_buf[..len].copy_from_slice(&input[..len]);
        }
        let amount_str = core::str::from_utf8(&amount_buf[..len]).unwrap_or("0");
        if mode == 0 {
            execute_stake(amount_str);
        } else {
            execute_unstake(amount_str);
        }
        return true;
    }
    if y >= 300 && y <= 332 && x >= w - 130 && x <= w - 40 {
        execute_claim();
        return true;
    }
    if y >= 380 && y <= 412 && x >= w - 130 && x <= w - 40 {
        execute_faucet();
        return true;
    }
    false
}

fn execute_stake(amount: &str) {
    set_status(b"Staking...", true);
    if super::rpc::stake_nox(amount).is_ok() {
        set_status(b"Stake submitted!", true);
        clear_stake_input();
        super::state::refresh_staking_data();
    } else {
        set_status(b"Stake failed", false);
    }
}

fn execute_unstake(amount: &str) {
    set_status(b"Unstaking...", true);
    if super::rpc::unstake_nox(amount).is_ok() {
        set_status(b"Unstake submitted!", true);
        clear_stake_input();
        super::state::refresh_staking_data();
    } else {
        set_status(b"Unstake failed", false);
    }
}

fn execute_claim() {
    set_status(b"Claiming rewards...", true);
    if super::rpc::claim_rewards().is_ok() {
        set_status(b"Claim submitted!", true);
        super::state::refresh_staking_data();
    } else {
        set_status(b"Claim failed", false);
    }
}

fn execute_faucet() {
    set_status(b"Requesting faucet...", true);
    if super::rpc::request_faucet().is_ok() {
        set_status(b"Faucet sent!", true);
    } else {
        set_status(b"Faucet failed", false);
    }
}

pub(crate) fn handle_staking_key(ch: u8) {
    if ch == b'.' || (ch >= b'0' && ch <= b'9') {
        let mut input = STAKE_INPUT.lock();
        let len = STAKE_INPUT_LEN.load(Ordering::SeqCst) as usize;
        if len < 20 {
            input[len] = ch;
            STAKE_INPUT_LEN.store((len + 1) as u8, Ordering::SeqCst);
        }
    }
}

pub(crate) fn handle_staking_backspace() {
    let len = STAKE_INPUT_LEN.load(Ordering::SeqCst) as usize;
    if len > 0 {
        STAKE_INPUT_LEN.store((len - 1) as u8, Ordering::SeqCst);
        STAKE_INPUT.lock()[len - 1] = 0;
    }
}
