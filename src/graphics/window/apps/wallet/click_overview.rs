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
use super::state_ops::{derive_account, set_active_account};

pub(super) fn handle_overview_click(x: u32, y: u32, w: u32) -> bool {
    if x >= w.saturating_sub(190) && x <= w.saturating_sub(110) && y >= 15 && y <= 47 {
        let s = WALLET_STATE.lock();
        let idx = s.accounts.len() as u32;
        drop(s);
        match derive_account(idx) {
            Ok(_) => set_status(b"Account created", true),
            Err(e) => set_status(e.as_bytes(), false),
        }
        return true;
    }
    if x >= w.saturating_sub(100) && x <= w.saturating_sub(20) && y >= 15 && y <= 47 {
        refresh_balances();
        return true;
    }
    if x >= 24 && x <= w.saturating_sub(24) && y >= 65 {
        let ci = (y.saturating_sub(65)) / 100;
        if (y.saturating_sub(65)) % 100 < 90 {
            let s = WALLET_STATE.lock();
            let cnt = s.accounts.len() as u32;
            drop(s);
            if ci < cnt {
                set_active_account(ci as usize);
                return true;
            }
        }
    }
    false
}

pub(super) fn handle_sidebar_click(y: u32) -> bool {
    if y < 90 {
        return false;
    }
    let i = (y - 90) / 52;
    let v = match i {
        0 => WalletView::Overview,
        1 => WalletView::Send,
        2 => WalletView::Receive,
        3 => WalletView::Staking,
        4 => WalletView::ZkSync,
        5 => WalletView::Transactions,
        6 => WalletView::Stealth,
        7 => WalletView::Settings,
        _ => return false,
    };
    set_view(v);
    if v == WalletView::Send {
        clear_send_fields();
    }
    true
}
