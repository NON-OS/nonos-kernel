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

use nonos_app_skeleton::PaintBuffer;

use crate::browser::paint::chrome::{buttons, constants, pill};
use crate::browser::state::State;

/* The toolbar: Back and Forward, lit when there is somewhere to go, Reload
 * (a Stop cross while a page loads), Home, the address pill and the menu. */
pub fn paint(state: &State, fb: &mut PaintBuffer) {
    fb.fill_rect(0, 0, fb.width, fb.height, constants::TOOLBAR_BG);
    let h = &state.ui.history;
    let lit = |on: bool| if on { constants::FG } else { constants::DIM };
    let back = h.can_back()
        || matches!(state.view, crate::browser::state::View::Home) && h.current().is_some();
    buttons::chevron(fb, constants::BACK_X as u32, false, lit(back));
    buttons::chevron(fb, constants::FWD_X as u32, true, lit(h.can_forward()));
    if state.loading() {
        buttons::stop(fb, constants::RELOAD_X as u32);
    } else {
        buttons::reload(fb, constants::RELOAD_X as u32);
    }
    buttons::home(fb, constants::HOME_X as u32);
    pill::pill(state, fb);
    buttons::hamburger(fb);
    fb.fill_rect(0, fb.height.saturating_sub(1), fb.width, 1, constants::ACCENT);
}
