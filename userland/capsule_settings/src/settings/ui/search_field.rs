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
use nonos_toolkit::icons::IconId;
use nonos_toolkit::widgets::{Field, Rect, State as Look};

use crate::settings::state::State;

use super::bytes::as_str;

pub const WIDTH: u32 = 236;

/// The toolkit field over the whole accessory, drawing the magnifier inside
/// its own body. The caret is at the end, where typing adds.
pub fn paint(fb: &mut PaintBuffer, state: &State) {
    let (w, h) = (fb.width, fb.height);
    let query = as_str(state.search.as_slice());
    let focused = state.search_focused;
    Field::new(query)
        .icon(IconId::SettingsSearch)
        .placeholder("Search settings")
        .caret(focused.then_some(query.len()))
        .state(Look { focused, ..Look::default() })
        .draw(fb, Rect { x: 0, y: 0, w, h });
}
