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
use crate::graphics::framebuffer::fill_rect;
use crate::graphics::window::draw_string;
use super::state::{STAKING_STATE, STAKE_INPUT, STAKE_INPUT_LEN, STAKE_MODE};
use crate::graphics::window::apps::wallet::render::{format_balance, COLOR_CARD, COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_ACCENT, COLOR_GREEN};
use crate::graphics::window::apps::wallet::render_views::draw_rounded_rect;

pub fn draw_staking_view(x: u32, y: u32, w: u32, _h: u32) {
    draw_string(x + 20, y + 20, b"NOX Staking", COLOR_TEXT_WHITE);
    let state = STAKING_STATE.lock();
    for shadow in 0..4u32 { draw_rounded_rect(x + 20 + shadow / 2, y + 50 + shadow + 2, w - 40, 100, 14, ((15 - shadow * 3) << 24) | 0x000000); }
    draw_rounded_rect(x + 20, y + 50, w - 40, 100, 14, COLOR_CARD);
    draw_string(x + 36, y + 70, b"Your Staked NOX", COLOR_TEXT_DIM);
    let (eth, wei) = ((state.staked_amount / 1_000_000_000_000_000_000) as u64, (state.staked_amount % 1_000_000_000_000_000_000 / 1_000_000_000_000_000) as u64);
    let mut buf = [0u8; 32]; let len = format_balance(&mut buf, eth, wei);
    draw_string(x + 36, y + 92, &buf[..len], COLOR_TEXT_WHITE);
    draw_string(x + 36 + (len as u32 + 1) * 8, y + 92, b"NOX", 0xFFBF5AF2);
    draw_string(x + 36, y + 120, b"Boost:", COLOR_TEXT_DIM);
    draw_string(x + 90, y + 120, state.boost_display(), COLOR_GREEN);
    draw_string(x + 140, y + 120, b"APY:", COLOR_TEXT_DIM);
    let mut apy_buf = [0u8; 8]; let apy_len = format_apy(&mut apy_buf, state.current_apy);
    draw_string(x + 180, y + 120, &apy_buf[..apy_len], COLOR_GREEN);
    drop(state);
    for shadow in 0..4u32 { draw_rounded_rect(x + 20 + shadow / 2, y + 165 + shadow + 2, w - 40, 120, 14, ((15 - shadow * 3) << 24) | 0x000000); }
    draw_rounded_rect(x + 20, y + 165, w - 40, 120, 14, COLOR_CARD);
    let mode = STAKE_MODE.load(Ordering::SeqCst);
    draw_rounded_rect(x + 36, y + 185, 80, 30, 8, if mode == 0 { COLOR_ACCENT } else { 0xFF3A3A3C });
    draw_string(x + 56, y + 193, b"Stake", if mode == 0 { 0xFF000000 } else { COLOR_TEXT_DIM });
    draw_rounded_rect(x + 126, y + 185, 80, 30, 8, if mode == 1 { COLOR_ACCENT } else { 0xFF3A3A3C });
    draw_string(x + 140, y + 193, b"Unstake", if mode == 1 { 0xFF000000 } else { COLOR_TEXT_DIM });
    draw_string(x + 36, y + 228, b"Amount:", COLOR_TEXT_DIM);
    draw_rounded_rect(x + 100, y + 222, w - 160, 28, 6, 0xFF1C1C1E);
    let input = STAKE_INPUT.lock(); let input_len = STAKE_INPUT_LEN.load(Ordering::SeqCst) as usize;
    draw_string(x + 112, y + 230, &input[..input_len], COLOR_TEXT_WHITE);
    drop(input);
    draw_rounded_rect(x + w / 2 - 50, y + 260, 100, 36, 10, if mode == 0 { COLOR_GREEN } else { 0xFFFF3B30 });
    draw_string(x + w / 2 - 24, y + 270, if mode == 0 { b"Stake" } else { b"Unstake" }, 0xFF000000);
    let state2 = STAKING_STATE.lock();
    for shadow in 0..4u32 { draw_rounded_rect(x + 20 + shadow / 2, y + 305 + shadow + 2, w - 40, 80, 14, ((15 - shadow * 3) << 24) | 0x000000); }
    draw_rounded_rect(x + 20, y + 305, w - 40, 80, 14, COLOR_CARD);
    draw_string(x + 36, y + 320, b"Pending Rewards (Mainnet)", COLOR_TEXT_DIM);
    let (rew_eth, rew_wei) = ((state2.pending_rewards / 1_000_000_000_000_000_000) as u64, (state2.pending_rewards % 1_000_000_000_000_000_000 / 1_000_000_000_000_000) as u64);
    let mut rew_buf = [0u8; 32]; let rew_len = format_balance(&mut rew_buf, rew_eth, rew_wei);
    draw_string(x + 36, y + 345, &rew_buf[..rew_len], COLOR_TEXT_WHITE);
    draw_string(x + 36 + (rew_len as u32 + 1) * 8, y + 345, b"NOX", 0xFFBF5AF2);
    draw_rounded_rect(x + w - 140, y + 335, 90, 32, 8, COLOR_GREEN);
    draw_string(x + w - 124, y + 345, b"Claim", 0xFF000000);
    drop(state2);
    for shadow in 0..4u32 { draw_rounded_rect(x + 20 + shadow / 2, y + 400 + shadow + 2, w - 40, 90, 14, ((15 - shadow * 3) << 24) | 0x000000); }
    draw_rounded_rect(x + 20, y + 400, w - 40, 90, 14, COLOR_CARD);
    draw_string(x + 36, y + 418, b"Sepolia Faucet", COLOR_TEXT_DIM);
    draw_string(x + 36, y + 440, b"Get free NOX tokens for testing", 0xFF8E8E93);
    draw_rounded_rect(x + w - 140, y + 432, 90, 32, 8, 0xFF5856D6);
    draw_string(x + w - 130, y + 442, b"Faucet", 0xFFFFFFFF);
    let state3 = STAKING_STATE.lock();
    let (pool_eth, pool_wei) = ((state3.total_pool_staked / 1_000_000_000_000_000_000) as u64, (state3.total_pool_staked % 1_000_000_000_000_000_000 / 1_000_000_000_000_000) as u64);
    let mut pool_buf = [0u8; 32]; let pool_len = format_balance(&mut pool_buf, pool_eth, pool_wei);
    draw_string(x + 36, y + 510, b"Pool:", COLOR_TEXT_DIM);
    draw_string(x + 80, y + 510, &pool_buf[..pool_len], COLOR_TEXT_WHITE);
    draw_string(x + 80 + (pool_len as u32 + 1) * 8, y + 510, b"NOX staked", 0xFF8E8E93);
}

fn format_apy(buf: &mut [u8; 8], apy_bps: u32) -> usize {
    let pct = apy_bps / 100; let mut i = 0;
    if pct >= 100 { buf[i] = b'0' + ((pct / 100) % 10) as u8; i += 1; }
    if pct >= 10 { buf[i] = b'0' + ((pct / 10) % 10) as u8; i += 1; }
    buf[i] = b'0' + (pct % 10) as u8; i += 1;
    buf[i] = b'%'; i += 1;
    i
}
