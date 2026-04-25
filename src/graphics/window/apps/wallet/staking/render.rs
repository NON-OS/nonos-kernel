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

use super::state::{STAKE_INPUT, STAKE_INPUT_LEN, STAKE_MODE, STAKING_STATE};
use crate::graphics::framebuffer::fill_rect;
use crate::graphics::window::apps::wallet::render::*;
use crate::graphics::window::apps::wallet::render_views::draw_rounded_rect;
use crate::graphics::window::draw_string;
use core::sync::atomic::Ordering;

pub(crate) fn draw_staking_view(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, COLOR_BG);
    draw_string(x + 24, y + 16, b"NOX Staking", COLOR_TEXT_WHITE);
    fill_rect(x + 24, y + 34, 80, 2, COLOR_PURPLE);
    draw_rounded_rect(x + w - 100, y + 12, 76, 28, 8, COLOR_ACCENT);
    draw_string(x + w - 88, y + 20, b"Refresh", 0xFF000000);
    let state = STAKING_STATE.lock();
    draw_rounded_rect(x + 24, y + 50, w - 48, 90, 12, COLOR_CARD);
    fill_rect(x + 24, y + 66, 3, 58, COLOR_PURPLE);
    draw_string(x + 40, y + 62, b"Your Staked Position", COLOR_TEXT_DIM);
    let mut buf = [0u8; 32];
    let (eth, wei) = (
        (state.staked_amount / 1_000_000_000_000_000_000) as u64,
        (state.staked_amount % 1_000_000_000_000_000_000 / 1_000_000_000_000_000) as u64,
    );
    let len = format_balance(&mut buf, eth, wei);
    draw_string(x + 40, y + 82, &buf[..len], COLOR_TEXT_WHITE);
    draw_string(x + 40 + (len as u32 + 1) * 8, y + 82, b"NOX", COLOR_PURPLE);
    draw_string(x + 40, y + 104, b"Boost:", COLOR_TEXT_DIM);
    draw_string(x + 96, y + 104, state.boost_display(), COLOR_GREEN);
    draw_string(x + 150, y + 104, b"NFTs:", COLOR_TEXT_DIM);
    draw_string(x + 196, y + 104, &format_nft_count(state.nft_count), COLOR_CYAN);
    let _share = if state.total_weighted > 0 {
        ((state.weighted_amount as u64 * 10000) / state.total_weighted as u64) as u32
    } else {
        0
    };
    let nft_count = state.nft_count;
    drop(state);
    if nft_count > 0 {
        draw_rounded_rect(x + w - 140, y + 58, 96, 74, 10, 0xFF2D1B4E);
        fill_rect(x + w - 138, y + 60, 92, 2, COLOR_PURPLE);
        draw_string(x + w - 130, y + 68, b"ZeroState", 0xFFE0B0FF);
        draw_string(x + w - 130, y + 82, b"Pass NFT", COLOR_PURPLE);
        draw_rounded_rect(x + w - 120, y + 100, 56, 24, 6, COLOR_PURPLE);
        draw_string(x + w - 110, y + 106, &format_nft_badge(nft_count), 0xFF000000);
    }
    draw_rounded_rect(x + 24, y + 155, w - 48, 110, 12, COLOR_CARD);
    fill_rect(x + 24, y + 171, 3, 78, COLOR_ACCENT);
    let mode = STAKE_MODE.load(Ordering::SeqCst);
    draw_rounded_rect(x + 40, y + 168, 80, 30, 8, if mode == 0 { COLOR_GREEN } else { 0xFF3A3A3C });
    draw_string(x + 60, y + 176, b"Stake", if mode == 0 { 0xFF000000 } else { COLOR_TEXT_DIM });
    draw_rounded_rect(x + 130, y + 168, 80, 30, 8, if mode == 1 { COLOR_RED } else { 0xFF3A3A3C });
    draw_string(x + 144, y + 176, b"Unstake", if mode == 1 { 0xFF000000 } else { COLOR_TEXT_DIM });
    draw_string(x + 40, y + 210, b"Amount:", COLOR_TEXT_DIM);
    draw_rounded_rect(x + 110, y + 204, w - 180, 26, 6, 0xFF1C1C1E);
    let input = STAKE_INPUT.lock();
    let input_len = STAKE_INPUT_LEN.load(Ordering::SeqCst) as usize;
    draw_string(x + 118, y + 211, &input[..input_len], COLOR_TEXT_WHITE);
    drop(input);
    draw_rounded_rect(
        x + w / 2 - 55,
        y + 238,
        110,
        34,
        10,
        if mode == 0 { COLOR_GREEN } else { COLOR_RED },
    );
    let btn_label: &[u8] = if mode == 0 { b"Stake NOX" } else { b"Unstake" };
    draw_string(x + w / 2 - 35, y + 248, btn_label, 0xFF000000);
    let state2 = STAKING_STATE.lock();
    draw_rounded_rect(x + 24, y + 280, w - 48, 70, 12, COLOR_CARD);
    fill_rect(x + 24, y + 296, 3, 38, COLOR_GREEN);
    draw_string(x + 40, y + 292, b"Pending Rewards", COLOR_TEXT_DIM);
    let (rew_eth, rew_wei) = (
        (state2.pending_rewards / 1_000_000_000_000_000_000) as u64,
        (state2.pending_rewards % 1_000_000_000_000_000_000 / 1_000_000_000_000_000) as u64,
    );
    let mut rew_buf = [0u8; 32];
    let rew_len = format_balance(&mut rew_buf, rew_eth, rew_wei);
    draw_string(x + 40, y + 314, &rew_buf[..rew_len], COLOR_TEXT_WHITE);
    draw_string(x + 40 + (rew_len as u32 + 1) * 8, y + 314, b"NOX", COLOR_GREEN);
    draw_rounded_rect(x + w - 130, y + 300, 90, 32, 8, COLOR_GREEN);
    draw_string(x + w - 108, y + 310, b"Claim", 0xFF000000);
    drop(state2);
    draw_rounded_rect(x + 24, y + 365, w - 48, 60, 12, COLOR_CARD);
    fill_rect(x + 24, y + 381, 3, 28, COLOR_CYAN);
    draw_string(x + 40, y + 377, b"Sepolia Faucet", COLOR_TEXT_DIM);
    draw_string(x + 40, y + 397, b"Get free NOX for testing", 0xFF6B6B7A);
    draw_rounded_rect(x + w - 130, y + 380, 90, 32, 8, COLOR_CYAN);
    draw_string(x + w - 112, y + 390, b"Faucet", 0xFF000000);
}

fn format_nft_count(count: u8) -> [u8; 1] {
    [b'0' + count.min(9)]
}

fn format_nft_badge(count: u8) -> [u8; 4] {
    let mut buf = [b'x', b' ', b' ', b' '];
    buf[1] = b'0' + count.min(9);
    buf
}
