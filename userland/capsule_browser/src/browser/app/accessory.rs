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

use nonos_app_skeleton::{EventOutcome, InputEvent, PaintBuffer};
use nonos_toolkit::decorations::BORDER_PX;

use super::browser::Browser;
use super::strip::strip_print;
use crate::browser::event::on_tabbar;
use crate::browser::paint::tabbar;
use crate::browser::shell::Page;
use crate::browser::ui::tabs_geom::{nominal_w, LIGHTS_RESERVE};

/* The titlebar's tab strip, hosted through the app skeleton's accessory. */
impl Browser {
    /* Every tab at full width, held clear of the window's traffic lights. */
    pub(super) fn accessory_w(&self) -> u32 {
        let want = nominal_w(self.tabs.list.len());
        match self.tabs.active().layout.toolbar.w {
            0 => want as u32,
            w => want.min(w + 2 * BORDER_PX as i32 - LIGHTS_RESERVE).max(0) as u32,
        }
    }

    pub(super) fn paint_strip(&mut self, fb: &mut PaintBuffer) {
        self.acc = (fb.width as i32, fb.height as i32);
        self.strip = strip_print(&self.tabs);
        tabbar::paint(&self.tabs, fb);
    }

    pub(super) fn strip_event(&mut self, event: InputEvent) -> EventOutcome {
        let group = crate::browser::tab_groups::inherit(&self.shell);
        let out = on_tabbar(&mut self.tabs, self.acc.0, self.acc.1, event, group);
        self.shown_tab(out)
    }

    /* What the strip shows has changed since it was last painted. */
    pub(super) fn strip_moved(&self) -> bool {
        strip_print(&self.tabs) != self.strip
    }

    /* A tab that was opened, closed or switched to is what the window shows. */
    pub(super) fn shown_tab(&mut self, out: EventOutcome) -> EventOutcome {
        if out == EventOutcome::Repaint {
            self.shell.show(Page::Web);
        }
        out
    }
}
