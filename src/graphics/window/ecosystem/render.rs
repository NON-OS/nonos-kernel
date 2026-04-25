// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::render_browser::draw_browser_tab;
use super::render_helpers::draw_error_toast;
use super::render_tabs::{
    draw_lp_tab, draw_node_tab, draw_privacy_tab, draw_staking_tab, draw_wallet_tab,
};
use super::state::{self, EcosystemTab};
use super::tabs;
use crate::graphics::framebuffer::fill_rect;

const COLOR_BG: u32 = 0xFF000000;

pub fn draw(x: u32, y: u32, w: u32, h: u32) {
    fill_rect(x, y, w, h, COLOR_BG);
    let active_tab = state::get_active_tab();
    tabs::draw_tab_bar(x, y, w, active_tab);
    let content_y = y + tabs::TAB_HEIGHT;
    let content_h = h.saturating_sub(tabs::TAB_HEIGHT);
    match active_tab {
        EcosystemTab::Browser => draw_browser_tab(x, content_y, w, content_h),
        EcosystemTab::Wallet => draw_wallet_tab(x, content_y, w, content_h),
        EcosystemTab::Staking => draw_staking_tab(x, content_y, w, content_h),
        EcosystemTab::Liquidity => draw_lp_tab(x, content_y, w, content_h),
        EcosystemTab::Node => draw_node_tab(x, content_y, w, content_h),
        EcosystemTab::Privacy => draw_privacy_tab(x, content_y, w, content_h),
    }
    if let Some(error) = state::get_error() {
        draw_error_toast(x, y + h - 60, w, &error);
    }
}

pub use super::render_utils::{format_balance, format_status};
