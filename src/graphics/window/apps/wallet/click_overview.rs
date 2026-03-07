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

use super::state::*;
use super::state_ops::set_active_account;

pub(super) fn handle_overview_click(x: u32, y: u32, w: u32) -> bool {
    if x >= w.saturating_sub(100) && x <= w.saturating_sub(20) && y >= 15 && y <= 43 {
        refresh_balances();
        return true;
    }

    if x >= 20 && x <= w.saturating_sub(20) && y >= 50 {
        let card_index = (y.saturating_sub(50)) / 80;
        let card_y_offset = (y.saturating_sub(50)) % 80;

        if card_y_offset < 70 {
            let state = WALLET_STATE.lock();
            let account_count = state.accounts.len() as u32;
            drop(state);

            if card_index < account_count {
                set_active_account(card_index as usize);
                return true;
            }
        }
    }

    false
}

pub(super) fn handle_sidebar_click(y: u32) -> bool {
    let menu_start = 60u32;
    let item_height = 36u32;

    if y < menu_start {
        return false;
    }

    let item_index = (y - menu_start) / item_height;
    let view = match item_index {
        0 => WalletView::Overview,
        1 => WalletView::Send,
        2 => WalletView::Receive,
        3 => WalletView::Transactions,
        4 => WalletView::Stealth,
        5 => WalletView::Settings,
        _ => return false,
    };

    set_view(view);
    if view == WalletView::Send {
        clear_send_fields();
    }
    true
}
