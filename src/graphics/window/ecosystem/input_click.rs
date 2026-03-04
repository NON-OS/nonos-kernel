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

use super::state;
use super::input_actions::{
    go_back, go_forward, reload, handle_link_click,
    create_new_wallet, import_wallet, send_transaction, show_receive_address, open_swap,
    stake_tokens, unstake_tokens, claim_rewards,
    add_liquidity, remove_liquidity, compound_lp,
    connect_node, disconnect_node, open_node_settings,
};

pub(super) fn handle_browser_click(x: u32, y: u32, w: u32, h: u32) -> bool {
    if y > h { return false; }
    if y >= 8 && y < 44 {
        let url_bar_x = 8 + 28 * 3 + 12 + 8;
        let url_bar_w = w - url_bar_x - 16;

        if x >= 8 && x < 8 + 28 {
            go_back();
            return true;
        }

        if x >= 8 + 32 && x < 8 + 32 + 28 {
            go_forward();
            return true;
        }

        if x >= 8 + 64 && x < 8 + 64 + 28 {
            reload();
            return true;
        }

        if x >= url_bar_x && x < url_bar_x + url_bar_w {
            state::URL_FOCUSED.store(true, Ordering::Relaxed);
            state::set_input_focused(true);

            let char_pos = ((x - url_bar_x - 8) / 8) as usize;
            let url_len = state::URL_LEN.load(Ordering::Relaxed);
            state::URL_CURSOR.store(char_pos.min(url_len), Ordering::Relaxed);
            return true;
        }
    }

    state::URL_FOCUSED.store(false, Ordering::Relaxed);
    state::set_input_focused(false);

    let content_y = 52;
    if y >= content_y {
        let content_rel_y = y - content_y;
        let line_height = 18;
        let clicked_line = (content_rel_y / line_height) as usize;
        let scroll = state::PAGE_SCROLL.load(Ordering::Relaxed);
        let actual_line = scroll + clicked_line;

        handle_link_click(actual_line, x);
    }

    true
}

pub(super) fn handle_wallet_click(x: u32, y: u32, w: u32, h: u32) -> bool {
    if y > h { return false; }
    let card_w = w.saturating_sub(32).min(600);
    let card_x = (w - card_w) / 2;

    let connected = state::WALLET_CONNECTED.load(Ordering::Relaxed);

    if !connected {
        if y >= 130 && y < 166 {
            if x >= card_x + 20 && x < card_x + 160 {
                create_new_wallet();
                return true;
            }
            if x >= card_x + 180 && x < card_x + 320 {
                import_wallet();
                return true;
            }
        }
    } else {
        if y >= 230 && y < 262 {
            if x >= card_x + 20 && x < card_x + 120 {
                send_transaction();
                return true;
            }
            if x >= card_x + 140 && x < card_x + 240 {
                show_receive_address();
                return true;
            }
            if x >= card_x + 260 && x < card_x + 360 {
                open_swap();
                return true;
            }
        }
    }

    true
}

pub(super) fn handle_staking_click(x: u32, y: u32, w: u32, h: u32) -> bool {
    if y > h { return false; }
    let card_w = w.saturating_sub(32).min(600);
    let card_x = (w - card_w) / 2;

    if y >= 250 && y < 282 {
        if x >= card_x + 20 && x < card_x + 120 {
            stake_tokens();
            return true;
        }
        if x >= card_x + 140 && x < card_x + 240 {
            unstake_tokens();
            return true;
        }
        if x >= card_x + 260 && x < card_x + 360 {
            claim_rewards();
            return true;
        }
    }

    true
}

pub(super) fn handle_lp_click(x: u32, y: u32, w: u32, h: u32) -> bool {
    if y > h { return false; }
    let card_w = w.saturating_sub(32).min(600);
    let card_x = (w - card_w) / 2;

    if y >= 230 && y < 262 {
        if x >= card_x + 20 && x < card_x + 140 {
            add_liquidity();
            return true;
        }
        if x >= card_x + 160 && x < card_x + 280 {
            remove_liquidity();
            return true;
        }
        if x >= card_x + 300 && x < card_x + 400 {
            compound_lp();
            return true;
        }
    }

    true
}

pub(super) fn handle_node_click(x: u32, y: u32, w: u32, h: u32) -> bool {
    if y > h { return false; }
    let card_w = w.saturating_sub(32).min(600);
    let card_x = (w - card_w) / 2;

    if y >= 325 && y < 353 {
        let connected = state::NODE_CONNECTED.load(Ordering::Relaxed);

        if x >= card_x + 20 && x < card_x + 140 {
            if connected {
                disconnect_node();
            } else {
                connect_node();
            }
            return true;
        }
        if x >= card_x + 160 && x < card_x + 280 {
            open_node_settings();
            return true;
        }
    }

    true
}

pub(super) fn handle_privacy_click(x: u32, y: u32, w: u32, h: u32) -> bool {
    if y > h { return false; }
    let card_w = w.saturating_sub(32).min(600);
    let card_x = (w - card_w) / 2;
    let _ = (x, card_w, card_x);

    true
}
