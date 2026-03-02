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

use crate::graphics::framebuffer::{
    COLOR_ACCENT, COLOR_GREEN, COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_YELLOW,
};
use crate::shell::output::print_line;
use crate::daemon::get_daemon_state;

use super::format::{print_prefixed, print_tier, print_number_line, print_token_amount};

pub fn cmd_stake_status() {
    print_line(b"NOX Staking", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);

    let state = get_daemon_state();
    let staking = &state.staking;

    print_tier(b"Tier: ", staking.tier());

    print_line(b"", COLOR_TEXT);
    print_line(b"Staked:", COLOR_ACCENT);
    print_token_amount(b"  ", &staking.total_staked());

    print_line(b"", COLOR_TEXT);
    print_line(b"Pending Rewards:", COLOR_ACCENT);
    print_token_amount(b"  ", &staking.pending_rewards);

    print_line(b"", COLOR_TEXT);
    print_line(b"Claimed Rewards:", COLOR_ACCENT);
    print_token_amount(b"  ", &staking.claimed_rewards);

    print_line(b"", COLOR_TEXT);
    print_number_line(b"Current Epoch: ", staking.current_epoch as u32, b"");
    print_number_line(b"Streak: ", staking.streak, b" epochs");
}

pub fn cmd_stake_deposit(_cmd: &[u8]) {
    print_line(b"Stake Deposit", COLOR_TEXT_WHITE);
    print_line(b"================================", COLOR_TEXT_DIM);
    print_line(b"", COLOR_TEXT);
    print_line(b"Connect wallet first", COLOR_YELLOW);
    print_line(b"Use 'wallet' to check status", COLOR_TEXT_DIM);
}

pub fn cmd_rewards_claim() {
    let mut state = get_daemon_state();

    match state.staking.claim_rewards() {
        Ok(amount) => {
            print_line(b"Rewards Claimed", COLOR_GREEN);
            print_token_amount(b"Amount: ", &amount);
        }
        Err(e) => {
            let msg = e.as_bytes();
            print_prefixed(b"Error: ", msg);
        }
    }
}
