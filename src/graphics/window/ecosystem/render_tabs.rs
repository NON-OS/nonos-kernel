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

use super::render_helpers::{
    draw_button, draw_card, draw_checkbox, draw_number, draw_progress_bar, draw_status_indicator,
    draw_string, draw_string_clipped, COLOR_ACCENT, COLOR_ERROR, COLOR_TEXT, COLOR_TEXT_BRIGHT,
    COLOR_TEXT_DIM, COLOR_WARNING,
};
use super::state;
use crate::graphics::font::draw_char;
use crate::graphics::window::apps::wallet::WALLET_STATE;
use core::sync::atomic::Ordering;

pub(super) fn draw_wallet_tab(x: u32, y: u32, w: u32, h: u32) {
    let card_w = w.saturating_sub(32).min(600);
    let card_x = x + (w - card_w) / 2;
    let max_y = y + h;
    if max_y < y + 300 {
        return;
    }

    let (unlocked, addr_hex, eth_balance, nox_balance) = {
        let state = WALLET_STATE.lock();
        if !state.unlocked {
            (false, [0u8; 42], 0u128, 0u128)
        } else if let Some(acc) = state.get_active_account() {
            (true, acc.address_hex(), acc.balance, acc.nox_balance)
        } else {
            (false, [0u8; 42], 0u128, 0u128)
        }
    };

    if !unlocked {
        draw_card(card_x, y + 20, card_w, 200);
        draw_string(card_x + 20, y + 40, b"N\\xd8NOS Wallet", COLOR_TEXT_BRIGHT);
        draw_string(card_x + 20, y + 70, b"Open the Wallet app to unlock", COLOR_TEXT_DIM);
        draw_string(card_x + 20, y + 90, b"and manage your accounts.", COLOR_TEXT_DIM);

        draw_button(card_x + 20, y + 130, 160, 36, b"Open Wallet App");
    } else {
        draw_card(card_x, y + 20, card_w, 160);
        draw_string(card_x + 20, y + 40, b"Active Wallet", COLOR_TEXT_DIM);
        draw_string_clipped(card_x + 20, y + 60, &addr_hex, COLOR_TEXT, card_w - 40);

        draw_string(card_x + 20, y + 95, b"ETH Balance", COLOR_TEXT_DIM);
        let wei_per: u128 = 1_000_000_000_000_000_000;
        let eth = (eth_balance / wei_per) as u64;
        let wei_frac = (eth_balance % wei_per / 1_000_000_000_000_000) as u64;
        let mut balance_str = [0u8; 32];
        let len = format_balance_simple(&mut balance_str, eth, wei_frac);
        for (i, &ch) in balance_str[..len].iter().enumerate() {
            draw_char(card_x + 20 + i as u32 * 8, y + 115, ch, COLOR_TEXT_BRIGHT);
        }
        draw_string(card_x + 20 + len as u32 * 8 + 8, y + 115, b"ETH", 0xFF34C759);

        draw_string(card_x + 20, y + 140, b"NOX Balance", COLOR_TEXT_DIM);
        let nox = (nox_balance / wei_per) as u64;
        let nox_frac = (nox_balance % wei_per / 1_000_000_000_000_000) as u64;
        let mut nox_str = [0u8; 32];
        let nox_len = format_balance_simple(&mut nox_str, nox, nox_frac);
        for (i, &ch) in nox_str[..nox_len].iter().enumerate() {
            draw_char(card_x + 20 + i as u32 * 8, y + 160, ch, COLOR_TEXT_BRIGHT);
        }
        draw_string(card_x + 20 + nox_len as u32 * 8 + 8, y + 160, b"NOX", 0xFFBF5AF2);

        draw_card(card_x, y + 200, card_w, 80);
        draw_string(card_x + 20, y + 220, b"Quick Actions", COLOR_TEXT_BRIGHT);
        draw_button(card_x + 20, y + 245, 120, 28, b"Open Wallet");
        draw_button(card_x + 160, y + 245, 100, 28, b"Refresh");
    }
}

fn format_balance_simple(buf: &mut [u8; 32], whole: u64, frac: u64) -> usize {
    let mut idx = 0;
    if whole == 0 {
        buf[idx] = b'0';
        idx += 1;
    } else {
        let mut n = whole;
        let mut digits = [0u8; 20];
        let mut dc = 0;
        while n > 0 {
            digits[dc] = (n % 10) as u8;
            n /= 10;
            dc += 1;
        }
        for i in (0..dc).rev() {
            buf[idx] = b'0' + digits[i];
            idx += 1;
        }
    }
    buf[idx] = b'.';
    idx += 1;
    buf[idx] = b'0' + ((frac / 100) % 10) as u8;
    idx += 1;
    buf[idx] = b'0' + ((frac / 10) % 10) as u8;
    idx += 1;
    buf[idx] = b'0' + (frac % 10) as u8;
    idx += 1;
    idx
}

pub(super) fn draw_staking_tab(x: u32, y: u32, w: u32, h: u32) {
    let card_w = w.saturating_sub(32).min(600);
    let card_x = x + (w - card_w) / 2;
    let max_y = y + h;
    if max_y < y + 420 {
        return;
    }

    draw_card(card_x, y + 20, card_w, 160);
    draw_string(card_x + 20, y + 40, b"NOX Staking", COLOR_TEXT_BRIGHT);

    draw_string(card_x + 20, y + 70, b"Staked Amount", COLOR_TEXT_DIM);
    if let Some(amount) = state::get_staking_amount() {
        let amount_bytes = amount.as_bytes();
        for (i, &ch) in amount_bytes.iter().enumerate() {
            draw_char(card_x + 20 + i as u32 * 8, y + 90, ch, COLOR_TEXT_BRIGHT);
        }
        draw_string(
            card_x + 20 + amount_bytes.len() as u32 * 8 + 8,
            y + 90,
            b"NOX",
            COLOR_TEXT_DIM,
        );
    } else {
        draw_string(card_x + 20, y + 90, b"0 NOX", COLOR_TEXT_BRIGHT);
    }

    draw_string(card_x + 20, y + 120, b"Pending Rewards", COLOR_TEXT_DIM);
    if let Some(rewards) = state::get_staking_rewards() {
        let rewards_bytes = rewards.as_bytes();
        for (i, &ch) in rewards_bytes.iter().enumerate() {
            draw_char(card_x + 20 + i as u32 * 8, y + 140, ch, COLOR_ACCENT);
        }
        draw_string(
            card_x + 20 + rewards_bytes.len() as u32 * 8 + 8,
            y + 140,
            b"NOX",
            COLOR_TEXT_DIM,
        );
    } else {
        draw_string(card_x + 20, y + 140, b"0 NOX", COLOR_ACCENT);
    }

    draw_card(card_x, y + 200, card_w, 100);
    draw_string(card_x + 20, y + 220, b"Stake Actions", COLOR_TEXT_BRIGHT);
    draw_button(card_x + 20, y + 250, 100, 32, b"Stake");
    draw_button(card_x + 140, y + 250, 100, 32, b"Unstake");
    draw_button(card_x + 260, y + 250, 100, 32, b"Claim");

    draw_card(card_x, y + 320, card_w, 80);
    draw_string(card_x + 20, y + 340, b"APY: ", COLOR_TEXT_DIM);
    draw_string(card_x + 60, y + 340, b"12.5%", COLOR_ACCENT);
    draw_string(card_x + 20, y + 365, b"Contract: ", COLOR_TEXT_DIM);
    draw_string(card_x + 100, y + 365, b"0x7c34...B652", COLOR_TEXT);
}

pub(super) fn draw_lp_tab(x: u32, y: u32, w: u32, h: u32) {
    let card_w = w.saturating_sub(32).min(600);
    let card_x = x + (w - card_w) / 2;
    let max_y = y + h;
    if max_y < y + 400 {
        return;
    }

    draw_card(card_x, y + 20, card_w, 140);
    draw_string(card_x + 20, y + 40, b"Liquidity Pool", COLOR_TEXT_BRIGHT);

    draw_string(card_x + 20, y + 70, b"Your LP Position", COLOR_TEXT_DIM);

    let lp_value_len = state::LP_TOTAL_VALUE_LEN.load(Ordering::Relaxed);
    if lp_value_len > 0 {
        let buf = state::LP_TOTAL_VALUE.lock();
        for (i, &ch) in buf[..lp_value_len].iter().enumerate() {
            draw_char(card_x + 20 + i as u32 * 8, y + 90, ch, COLOR_TEXT_BRIGHT);
        }
        draw_string(card_x + 20 + lp_value_len as u32 * 8 + 8, y + 90, b"USD", COLOR_TEXT_DIM);
    } else {
        draw_string(card_x + 20, y + 90, b"$0.00", COLOR_TEXT_BRIGHT);
    }

    draw_string(card_x + 20, y + 120, b"APY: ", COLOR_TEXT_DIM);
    let apy_len = state::LP_APY_LEN.load(Ordering::Relaxed);
    if apy_len > 0 {
        let buf = state::LP_APY.lock();
        for (i, &ch) in buf[..apy_len].iter().enumerate() {
            draw_char(card_x + 60 + i as u32 * 8, y + 120, ch, COLOR_ACCENT);
        }
    } else {
        draw_string(card_x + 60, y + 120, b"8.2%", COLOR_ACCENT);
    }

    draw_card(card_x, y + 180, card_w, 100);
    draw_string(card_x + 20, y + 200, b"Pool Actions", COLOR_TEXT_BRIGHT);
    draw_button(card_x + 20, y + 230, 120, 32, b"Add Liquidity");
    draw_button(card_x + 160, y + 230, 120, 32, b"Remove");
    draw_button(card_x + 300, y + 230, 100, 32, b"Compound");

    draw_card(card_x, y + 300, card_w, 80);
    draw_string(card_x + 20, y + 320, b"Pool: ETH/NOX", COLOR_TEXT);
    draw_string(card_x + 20, y + 345, b"Contract: ", COLOR_TEXT_DIM);
    draw_string(card_x + 100, y + 345, b"0x3322...874E", COLOR_TEXT);
}

pub(super) fn draw_node_tab(x: u32, y: u32, w: u32, h: u32) {
    let card_w = w.saturating_sub(32).min(600);
    let card_x = x + (w - card_w) / 2;
    let max_y = y + h;
    if max_y < y + 400 {
        return;
    }

    let connected = state::NODE_CONNECTED.load(Ordering::Relaxed);

    draw_card(card_x, y + 20, card_w, 120);
    draw_string(card_x + 20, y + 40, b"Node Status", COLOR_TEXT_BRIGHT);

    let syncing = state::NODE_SYNC_PROGRESS.load(Ordering::Relaxed) < 100;
    let status_color = if connected && !syncing {
        COLOR_ACCENT
    } else if connected {
        COLOR_WARNING
    } else {
        COLOR_ERROR
    };
    draw_status_indicator(card_x + 20, y + 70, status_color);
    if connected && !syncing {
        draw_string(card_x + 40, y + 70, b"Connected", status_color);
    } else if connected {
        draw_string(card_x + 40, y + 70, b"Syncing", status_color);
    } else {
        draw_string(card_x + 40, y + 70, b"Disconnected", status_color);
    }

    if connected {
        let peers = state::NODE_PEERS.load(Ordering::Relaxed);
        let block_height = state::NODE_BLOCK_HEIGHT.load(Ordering::Relaxed);

        draw_string(card_x + 20, y + 95, b"Peers: ", COLOR_TEXT_DIM);
        draw_number(card_x + 76, y + 95, peers, COLOR_TEXT);

        draw_string(card_x + 20, y + 115, b"Block: ", COLOR_TEXT_DIM);
        draw_number(card_x + 76, y + 115, block_height, COLOR_TEXT);
    }

    draw_card(card_x, y + 160, card_w, 100);
    draw_string(card_x + 20, y + 180, b"Sync Progress", COLOR_TEXT_BRIGHT);

    let progress = state::NODE_SYNC_PROGRESS.load(Ordering::Relaxed);
    draw_progress_bar(card_x + 20, y + 210, card_w - 40, 20, progress);

    draw_card(card_x, y + 280, card_w, 80);
    draw_string(card_x + 20, y + 300, b"Node Controls", COLOR_TEXT_BRIGHT);
    if connected {
        draw_button(card_x + 20, y + 325, 120, 28, b"Disconnect");
    } else {
        draw_button(card_x + 20, y + 325, 120, 28, b"Connect");
    }
    draw_button(card_x + 160, y + 325, 120, 28, b"Settings");
}

pub(super) fn draw_privacy_tab(x: u32, y: u32, w: u32, h: u32) {
    let card_w = w.saturating_sub(32).min(600);
    let card_x = x + (w - card_w) / 2;
    let max_y = y + h;
    if max_y < y + 300 {
        return;
    }

    draw_card(card_x, y + 20, card_w, 180);
    draw_string(card_x + 20, y + 40, b"Privacy Statistics", COLOR_TEXT_BRIGHT);

    let trackers = state::PRIVACY_TRACKERS_BLOCKED.load(Ordering::Relaxed);
    let ads = state::PRIVACY_ADS_BLOCKED.load(Ordering::Relaxed);
    let urls = state::PRIVACY_URLS_CLEANED.load(Ordering::Relaxed);

    draw_string(card_x + 20, y + 75, b"Trackers Blocked:", COLOR_TEXT_DIM);
    draw_number(card_x + 180, y + 75, trackers, COLOR_ACCENT);

    draw_string(card_x + 20, y + 100, b"Ads Blocked:", COLOR_TEXT_DIM);
    draw_number(card_x + 180, y + 100, ads, COLOR_ACCENT);

    draw_string(card_x + 20, y + 125, b"URLs Cleaned:", COLOR_TEXT_DIM);
    draw_number(card_x + 180, y + 125, urls, COLOR_ACCENT);

    draw_string(card_x + 20, y + 160, b"Session Privacy Score: ", COLOR_TEXT_DIM);
    draw_string(card_x + 208, y + 160, b"Excellent", COLOR_ACCENT);

    draw_card(card_x, y + 220, card_w, 160);
    draw_string(card_x + 20, y + 240, b"Active Protections", COLOR_TEXT_BRIGHT);

    draw_checkbox(card_x + 20, y + 270, true);
    draw_string(card_x + 48, y + 270, b"Tracker Blocking", COLOR_TEXT);

    draw_checkbox(card_x + 20, y + 295, true);
    draw_string(card_x + 48, y + 295, b"URL Parameter Stripping", COLOR_TEXT);

    draw_checkbox(card_x + 20, y + 320, true);
    draw_string(card_x + 48, y + 320, b"JavaScript Disabled", COLOR_TEXT);

    draw_checkbox(card_x + 20, y + 345, false);
    draw_string(card_x + 48, y + 345, b"Onion Routing", COLOR_TEXT_DIM);
}
