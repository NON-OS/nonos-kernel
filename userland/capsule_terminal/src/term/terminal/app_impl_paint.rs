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

use crate::term::prefs::RAIL_VISIBLE;
use crate::term::theme::choice;
use nonos_app_skeleton::PaintBuffer;

use super::types::Terminal;
impl Terminal {
    pub(super) fn paint_inner(&mut self, fb: &mut PaintBuffer) {
        self.width = fb.width;
        let (theme, ansi) = choice::resolve(self.theme);
        let theme = &theme;
        let rail_open = self.prefs.rails & RAIL_VISIBLE != 0;
        let (cols, rows, m) = crate::paint::grid_size(fb, self.font_scale, rail_open);
        let key = choice::key(self.theme);
        let sb = &mut self.cur().scrollback;
        let resized = sb.fit(cols, rows, m.adv, m.lh);
        sb.follow_theme(key, theme, &ansi);
        if resized {
            crate::jobs::tty::resized(self.cur_ref());
        }
        let l = crate::paint::paint_tabs(
            &self.tabs,
            self.active,
            fb,
            theme,
            self.font_scale,
            &self.rail,
            self.prefs.project_slice(),
            self.prefs.rails & 1 == 0,
            self.rail_scroll,
            &self.palette,
            self.prefs.rails & RAIL_VISIBLE != 0,
        );
        let s = self.cur_ref();
        let owned = s.scrollback.vt.alt_active() || s.fg_running;
        self.cells = Some(super::pointer::CellGeom {
            x: l.body.x + crate::paint::TEXT_LEFT,
            y: l.body.y,
            adv: m.adv,
            lh: m.lh,
            pad: crate::paint::TEXT_LEFT,
            shell_rows: (l.body.h / m.lh.max(1)) as usize,
            owned,
        });
        self.layout = Some(l);
    }
}
