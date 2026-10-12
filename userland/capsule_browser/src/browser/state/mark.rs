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

use crate::browser::omnibox::{bits, Change, Focus};

use super::State;

impl State {
    /* Record a visible change; the next repaint draws what it dirtied. */
    pub fn mark(&mut self, c: Change) {
        self.track.damage.add(bits(c));
        self.track.paint_gen = self.track.paint_gen.wrapping_add(1);
    }

    /* The address bar text changed: the start page search pill mirrors it. */
    pub fn mark_omnibox(&mut self) {
        let c = if self.on_start { Change::HomeEdit } else { Change::OmniboxEdit };
        self.mark(c);
    }

    /* Give the address bar the keyboard, selecting its text so typing
     * replaces it, as every mainstream browser does. */
    pub fn focus_omnibox(&mut self) {
        self.focus = None;
        self.ui.kbd = Focus::Omnibox;
        self.ui.omnibox.select_all();
        self.mark(Change::Toolbar);
        self.mark_omnibox();
    }

    /* Give the page the keyboard, with `field` the focused form field. */
    pub fn focus_page(&mut self, field: Option<usize>) {
        if self.ui.kbd == Focus::Page && self.focus == field {
            return;
        }
        if self.ui.kbd == Focus::Omnibox {
            self.ui.omnibox.caret_to_end();
            self.mark(Change::Toolbar);
            self.mark_omnibox();
        }
        self.ui.kbd = Focus::Page;
        self.focus = field;
    }

    /* Show `url` in the address bar unless the reader is typing there. */
    pub fn show_url(&mut self, url: &str) {
        if self.ui.kbd == Focus::Omnibox {
            return;
        }
        self.ui.omnibox.set(url);
        self.ui.text_off = 0;
        self.mark_omnibox();
    }
}
