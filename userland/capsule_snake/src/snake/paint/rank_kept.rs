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
use nonos_toolkit::theme::roles;

use crate::snake::state::kept::line;
use crate::snake::state::Game;
use crate::snake::ui::metrics::PX_BODY;
use crate::snake::ui::rank_geom::kept_note;
use crate::snake::ui::text;

// Beside Back: whether the ranks reached the disk, stayed in memory until
// power off, or were not written or read, with the reason in the vfs's words.
pub fn paint(game: &Game, fb: &mut PaintBuffer) {
    let theme = roles();
    let (caption, why, warn) = line(game.kept);
    if caption.is_empty() {
        return;
    }
    let r = kept_note(fb.width, fb.height);
    let ink = if warn { theme.warn.argb() } else { theme.muted.argb() };
    let top = text::centred_top(r.1, r.3, PX_BODY);
    let cap = text::fit(caption, PX_BODY, r.2);
    let used = text::width_of(cap, PX_BODY);
    text::left(fb, r.0, top, cap, ink, PX_BODY);
    if cap.len() == caption.len() && !why.is_empty() {
        let rest = text::fit(why, PX_BODY, r.2.saturating_sub(used));
        text::left(fb, r.0 + used, top, rest, ink, PX_BODY);
    }
}
