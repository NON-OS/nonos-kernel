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
use crate::browser::net::mixnet::Network;
use crate::browser::ui::limits::TOOLBAR_H;

pub(super) const PANEL_W: i32 = 300;
pub(super) const PANEL_H: i32 = 256;
pub(super) const PANEL_TOP: i32 = TOOLBAR_H + 4;
pub(super) const ROW_H: i32 = 30;
pub(super) const ROW_STEP: i32 = 36;
pub(super) const FIRST_ROW_Y: i32 = PANEL_TOP + 70;
/* The three networks, top to bottom, then the proxy row and the search line. */
pub(super) const ROWS: [Network; 3] = [Network::Direct, Network::Nym, Network::Anyone];
pub(super) const PROXY_Y: i32 = FIRST_ROW_Y + 3 * ROW_STEP;
pub(super) const SEARCH_Y: i32 = PROXY_Y + 44;

pub(super) fn panel_x(width: i32) -> i32 {
    width - PANEL_W - 12
}

pub(super) enum Action {
    Choose(Network),
    Proxy,
    Close,
    Ignore,
}

pub(super) fn action_at(x: i32, y: i32, width: i32) -> Action {
    let px = panel_x(width);
    let inside = x >= px && x < px + PANEL_W && y >= PANEL_TOP && y < PANEL_TOP + PANEL_H;
    if !inside {
        return Action::Close;
    }
    let row = |top: i32| y >= top && y < top + ROW_H;
    for (i, net) in ROWS.iter().enumerate() {
        if row(FIRST_ROW_Y + i as i32 * ROW_STEP) {
            return Action::Choose(*net);
        }
    }
    match row(PROXY_Y) {
        true => Action::Proxy,
        false => Action::Ignore,
    }
}
