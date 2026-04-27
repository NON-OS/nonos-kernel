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

pub(super) fn handle_zksync_click(x: u32, y: u32, _w: u32) -> bool {
    if y >= 230 && y <= 266 {
        if x >= 36 && x <= 136 {
            set_status(b"L2 Bridge coming soon", true);
            return true;
        }
        if x >= 150 && x <= 250 {
            set_view(WalletView::Send);
            return true;
        }
        if x >= 264 && x <= 364 {
            set_view(WalletView::Receive);
            return true;
        }
    }
    false
}
