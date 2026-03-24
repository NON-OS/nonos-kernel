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
use crate::graphics::framebuffer::{fill_rect, put_pixel};
use crate::graphics::window::draw_string;
use super::state::{STAKING_STATE, STAKE_INPUT, STAKE_INPUT_LEN, STAKE_MODE};
use crate::graphics::window::apps::wallet::render::*;
use crate::graphics::window::apps::wallet::render_views::draw_rounded_rect;

pub fn draw_staking_view(x: u32, y: u32, w: u32, _h: u32) {
    draw_section_header(x + 24, y + 20, b"NOX Staking");
    let state = STAKING_STATE.lock();
    draw_staking_stats_card(x + 24, y + 60, w - 48, 110, &state);
    drop(state);
    draw_stake_action_card(x + 24, y + 185, w - 48, 140);
    let state2 = STAKING_STATE.lock();
    draw_rewards_card(x + 24, y + 340, w - 48, 95, &state2);
    drop(state2);
    draw_faucet_card(x + 24, y + 450, w - 48, 85);
}

fn draw_section_header(x: u32, y: u32, text: &[u8]) {
    draw_string(x, y, text, COLOR_TEXT_WHITE);
    fill_rect(x, y + 20, 80, 2, COLOR_PURPLE);
    for i in 0..4 { fill_rect(x + 80 + i * 2, y + 20, 1, 2, blend_alpha(COLOR_PURPLE, 60 - i * 15)); }
}

fn draw_staking_stats_card(x: u32, y: u32, w: u32, h: u32, state: &super::state::StakingState) {
    draw_premium_card(x, y, w, h, COLOR_PURPLE);
    draw_string(x + 20, y + 16, b"Your Staked Position", COLOR_TEXT_DIM);
    let (eth, wei) = ((state.staked_amount / 1_000_000_000_000_000_000) as u64, (state.staked_amount % 1_000_000_000_000_000_000 / 1_000_000_000_000_000) as u64);
    let mut buf = [0u8; 32];
    let len = format_balance(&mut buf, eth, wei);
    draw_string(x + 20, y + 42, &buf[..len], COLOR_TEXT_WHITE);
    draw_string(x + 20 + (len as u32 + 1) * 8, y + 42, b"NOX", COLOR_PURPLE_GLOW);
    draw_stat_pill(x + 20, y + 70, b"Boost", state.boost_display(), COLOR_GREEN);
    draw_stat_pill(x + 120, y + 70, b"APY", &format_apy_buf(state.current_apy), COLOR_YELLOW);
    let (pool_eth, pool_wei) = ((state.total_pool_staked / 1_000_000_000_000_000_000) as u64, (state.total_pool_staked % 1_000_000_000_000_000_000 / 1_000_000_000_000_000) as u64);
    let mut pool_buf = [0u8; 32];
    let pool_len = format_balance(&mut pool_buf, pool_eth, pool_wei);
    draw_string(x + w - 180, y + 42, b"Pool Total:", COLOR_TEXT_DIM);
    draw_string(x + w - 180, y + 62, &pool_buf[..pool_len], COLOR_TEXT_SECONDARY);
}

fn draw_stake_action_card(x: u32, y: u32, w: u32, h: u32) {
    draw_premium_card(x, y, w, h, COLOR_ACCENT);
    let mode = STAKE_MODE.load(Ordering::SeqCst);
    draw_tab_button(x + 20, y + 16, 90, 34, b"Stake", mode == 0, COLOR_GREEN);
    draw_tab_button(x + 120, y + 16, 90, 34, b"Unstake", mode == 1, COLOR_RED);
    draw_string(x + 20, y + 65, b"Amount", COLOR_TEXT_DIM);
    draw_input_field(x + 20, y + 85, w - 40, 36);
    let input = STAKE_INPUT.lock();
    let input_len = STAKE_INPUT_LEN.load(Ordering::SeqCst) as usize;
    draw_string(x + 32, y + 97, &input[..input_len], COLOR_TEXT_WHITE);
    drop(input);
    draw_action_button(x + w / 2 - 60, y + h - 50, 120, 40, if mode == 0 { b"Stake NOX" } else { b"Unstake" }, if mode == 0 { COLOR_GREEN } else { COLOR_RED });
}

fn draw_rewards_card(x: u32, y: u32, w: u32, h: u32, state: &super::state::StakingState) {
    draw_premium_card(x, y, w, h, COLOR_GREEN);
    draw_string(x + 20, y + 16, b"Pending Rewards (Mainnet)", COLOR_TEXT_DIM);
    let (rew_eth, rew_wei) = ((state.pending_rewards / 1_000_000_000_000_000_000) as u64, (state.pending_rewards % 1_000_000_000_000_000_000 / 1_000_000_000_000_000) as u64);
    let mut rew_buf = [0u8; 32];
    let rew_len = format_balance(&mut rew_buf, rew_eth, rew_wei);
    draw_string(x + 20, y + 42, &rew_buf[..rew_len], COLOR_TEXT_WHITE);
    draw_string(x + 20 + (rew_len as u32 + 1) * 8, y + 42, b"NOX", COLOR_GREEN_GLOW);
    draw_action_button(x + w - 120, y + 35, 100, 38, b"Claim", COLOR_GREEN);
}

fn draw_faucet_card(x: u32, y: u32, w: u32, h: u32) {
    draw_premium_card(x, y, w, h, COLOR_CYAN);
    draw_string(x + 20, y + 16, b"Sepolia Testnet Faucet", COLOR_TEXT_DIM);
    draw_string(x + 20, y + 40, b"Get free NOX tokens for testing", COLOR_TEXT_SECONDARY);
    draw_action_button(x + w - 120, y + 30, 100, 38, b"Faucet", COLOR_CYAN);
}

fn draw_premium_card(x: u32, y: u32, w: u32, h: u32, accent: u32) {
    for i in 0..6 { draw_rounded_rect(x + i / 2, y + 4 + i, w, h, 14, blend_alpha(0x000000, 25 - i * 4)); }
    draw_rounded_rect(x, y, w, h, 14, COLOR_CARD);
    draw_card_accent_line(x, y, h, accent);
    draw_card_top_glow(x, y, w, 14);
}

fn draw_card_accent_line(x: u32, y: u32, h: u32, color: u32) {
    fill_rect(x, y + 16, 4, h - 32, color);
    for i in 0..3 {
        put_pixel(x, y + 16 - 1 + i, blend_alpha(color, 70 - i * 20));
        put_pixel(x, y + h - 16 + i, blend_alpha(color, 70 - i * 20));
    }
}

fn draw_card_top_glow(x: u32, y: u32, w: u32, r: u32) {
    for row in 0..core::cmp::min(18, r + 8) {
        let alpha = 10 - (row as u32 * 10 / 18);
        if alpha == 0 { break; }
        let in_radius = row < r;
        let start_x = if in_radius { x + r - isqrt(r * r - (r - row) * (r - row)) } else { x };
        let end_x = if in_radius { x + w - r + isqrt(r * r - (r - row) * (r - row)) } else { x + w };
        if end_x > start_x { fill_rect(start_x, y + row, end_x - start_x, 1, blend_alpha(0xFFFFFF, alpha)); }
    }
}

fn draw_stat_pill(x: u32, y: u32, label: &[u8], value: &[u8], color: u32) {
    let w = (label.len() + value.len() + 2) as u32 * 8 + 20;
    draw_rounded_rect(x, y, w, 26, 8, blend_alpha(color, 20));
    draw_string(x + 10, y + 7, label, COLOR_TEXT_DIM);
    draw_string(x + 10 + (label.len() as u32 + 1) * 8, y + 7, value, color);
}

fn draw_tab_button(x: u32, y: u32, w: u32, h: u32, text: &[u8], active: bool, color: u32) {
    let bg = if active { color } else { COLOR_CARD_ELEVATED };
    draw_rounded_rect(x, y, w, h, 10, bg);
    if active { draw_button_glow(x, y, w, h, color); }
    let text_color = if active { 0xFF000000 } else { COLOR_TEXT_DIM };
    let text_x = x + (w - text.len() as u32 * 8) / 2;
    draw_string(text_x, y + (h - 12) / 2, text, text_color);
}

fn draw_button_glow(x: u32, y: u32, w: u32, _h: u32, color: u32) {
    for row in 0..8 {
        let alpha = 35 - row * 4;
        fill_rect(x + 2, y + row, w - 4, 1, blend_alpha(0xFFFFFF, alpha));
    }
    for i in 1..3 {
        fill_rect(x.saturating_sub(i), y, i, 1, blend_alpha(color, 20 - i * 6));
        fill_rect(x + w, y, i, 1, blend_alpha(color, 20 - i * 6));
    }
}

fn draw_input_field(x: u32, y: u32, w: u32, h: u32) {
    draw_rounded_rect(x, y, w, h, 10, COLOR_BG_DARK);
    for i in 0..2 { draw_rounded_rect(x + i, y + i, w - i * 2, h - i * 2, 10 - i, blend_alpha(COLOR_BORDER, 40 - i * 15)); }
}

fn draw_action_button(x: u32, y: u32, w: u32, h: u32, text: &[u8], color: u32) {
    for i in 0..4 { draw_rounded_rect(x + i / 2, y + 2 + i, w, h, 10, blend_alpha(0x000000, 20 - i * 4)); }
    draw_rounded_rect(x, y, w, h, 10, color);
    for row in 0..8 {
        let alpha = 40 - row * 5;
        fill_rect(x + 3, y + row, w - 6, 1, blend_alpha(0xFFFFFF, alpha));
    }
    let text_x = x + (w - text.len() as u32 * 8) / 2;
    draw_string(text_x, y + (h - 12) / 2, text, 0xFF000000);
}

fn format_apy_buf(apy_bps: u32) -> [u8; 6] {
    let pct = apy_bps / 100;
    let mut buf = [b' '; 6];
    let mut i = 0;
    if pct >= 100 { buf[i] = b'0' + ((pct / 100) % 10) as u8; i += 1; }
    if pct >= 10 { buf[i] = b'0' + ((pct / 10) % 10) as u8; i += 1; }
    buf[i] = b'0' + (pct % 10) as u8;
    i += 1;
    buf[i] = b'%';
    buf
}

fn blend_alpha(color: u32, alpha: u32) -> u32 { let a = (alpha * 255 / 100).min(255); (a << 24) | (color & 0x00FFFFFF) }
fn isqrt(n: u32) -> u32 { if n == 0 { return 0; } let mut x = n; let mut y = (x + 1) / 2; while y < x { x = y; y = (x + n / x) / 2; } x }
