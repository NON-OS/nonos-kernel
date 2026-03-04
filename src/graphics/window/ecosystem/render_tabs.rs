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
use crate::graphics::font::draw_char;
use super::state;
use super::render_helpers::{
    draw_card, draw_button, draw_string, draw_number, draw_checkbox,
    draw_status_indicator, draw_progress_bar,
    COLOR_TEXT, COLOR_TEXT_DIM, COLOR_TEXT_BRIGHT, COLOR_ACCENT, COLOR_WARNING, COLOR_ERROR,
};

pub(super) fn draw_wallet_tab(x: u32, y: u32, w: u32, h: u32) {
    let card_w = w.saturating_sub(32).min(600);
    let card_x = x + (w - card_w) / 2;
    let max_y = y + h;

    let connected = state::WALLET_CONNECTED.load(Ordering::Relaxed);
    if max_y < y + 300 { return; }

    if !connected {
        draw_card(card_x, y + 20, card_w, 200);
        draw_string(card_x + 20, y + 40, b"Connect Wallet", COLOR_TEXT_BRIGHT);
        draw_string(card_x + 20, y + 70, b"Create or import a wallet to access", COLOR_TEXT_DIM);
        draw_string(card_x + 20, y + 90, b"DeFi features.", COLOR_TEXT_DIM);

        draw_button(card_x + 20, y + 130, 140, 36, b"Create New");
        draw_button(card_x + 180, y + 130, 140, 36, b"Import");
    } else {
        draw_card(card_x, y + 20, card_w, 140);
        draw_string(card_x + 20, y + 40, b"Wallet Address", COLOR_TEXT_DIM);

        if let Some(addr) = state::get_wallet_address() {
            let addr_bytes = addr.as_bytes();
            let display_len = addr_bytes.len().min(42);
            for (i, &ch) in addr_bytes[..display_len].iter().enumerate() {
                draw_char(card_x + 20 + i as u32 * 8, y + 60, ch, COLOR_TEXT);
            }
        }

        draw_string(card_x + 20, y + 90, b"Balance", COLOR_TEXT_DIM);
        if let Some(balance) = state::get_wallet_balance() {
            let balance_bytes = balance.as_bytes();
            for (i, &ch) in balance_bytes.iter().enumerate() {
                draw_char(card_x + 20 + i as u32 * 8, y + 110, ch, COLOR_TEXT_BRIGHT);
            }
            draw_string(card_x + 20 + balance_bytes.len() as u32 * 8 + 8, y + 110, b"ETH", COLOR_TEXT_DIM);
        } else {
            draw_string(card_x + 20, y + 110, b"0.00 ETH", COLOR_TEXT_BRIGHT);
        }

        draw_card(card_x, y + 180, card_w, 100);
        draw_string(card_x + 20, y + 200, b"Actions", COLOR_TEXT_BRIGHT);
        draw_button(card_x + 20, y + 230, 100, 32, b"Send");
        draw_button(card_x + 140, y + 230, 100, 32, b"Receive");
        draw_button(card_x + 260, y + 230, 100, 32, b"Swap");
    }
}

pub(super) fn draw_staking_tab(x: u32, y: u32, w: u32, h: u32) {
    let card_w = w.saturating_sub(32).min(600);
    let card_x = x + (w - card_w) / 2;
    let max_y = y + h;
    if max_y < y + 420 { return; }

    draw_card(card_x, y + 20, card_w, 160);
    draw_string(card_x + 20, y + 40, b"NOX Staking", COLOR_TEXT_BRIGHT);

    draw_string(card_x + 20, y + 70, b"Staked Amount", COLOR_TEXT_DIM);
    if let Some(amount) = state::get_staking_amount() {
        let amount_bytes = amount.as_bytes();
        for (i, &ch) in amount_bytes.iter().enumerate() {
            draw_char(card_x + 20 + i as u32 * 8, y + 90, ch, COLOR_TEXT_BRIGHT);
        }
        draw_string(card_x + 20 + amount_bytes.len() as u32 * 8 + 8, y + 90, b"NOX", COLOR_TEXT_DIM);
    } else {
        draw_string(card_x + 20, y + 90, b"0 NOX", COLOR_TEXT_BRIGHT);
    }

    draw_string(card_x + 20, y + 120, b"Pending Rewards", COLOR_TEXT_DIM);
    if let Some(rewards) = state::get_staking_rewards() {
        let rewards_bytes = rewards.as_bytes();
        for (i, &ch) in rewards_bytes.iter().enumerate() {
            draw_char(card_x + 20 + i as u32 * 8, y + 140, ch, COLOR_ACCENT);
        }
        draw_string(card_x + 20 + rewards_bytes.len() as u32 * 8 + 8, y + 140, b"NOX", COLOR_TEXT_DIM);
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
    if max_y < y + 400 { return; }

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
    if max_y < y + 400 { return; }

    let connected = state::NODE_CONNECTED.load(Ordering::Relaxed);

    draw_card(card_x, y + 20, card_w, 120);
    draw_string(card_x + 20, y + 40, b"Node Status", COLOR_TEXT_BRIGHT);

    let syncing = state::NODE_SYNC_PROGRESS.load(Ordering::Relaxed) < 100;
    let status_color = if connected && !syncing { COLOR_ACCENT } else if connected { COLOR_WARNING } else { COLOR_ERROR };
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
    if max_y < y + 300 { return; }

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
