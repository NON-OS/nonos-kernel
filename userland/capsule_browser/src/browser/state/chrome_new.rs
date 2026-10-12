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

use alloc::string::String;

use super::{Chrome, Origin, PaintTrack};
use crate::browser::omnibox::{Damage, Focus, History, LineEdit};

impl Chrome {
    pub fn new() -> Self {
        Chrome {
            omnibox: LineEdit::new(),
            /* The window opens on the home page with the caret in the
             * address bar, ready to type. */
            kbd: Focus::Omnibox,
            current_url: String::new(),
            last_target: String::new(),
            history: History::new(),
            search: String::from(crate::browser::shell::search::DEFAULT_SEARCH),
            text_off: 0,
            hover_href: None,
            notice: None,
            select: None,
            truncated: false,
            nav_gen: 0,
            loading_gen: 0,
            origin: Origin::Auto,
        }
    }
}

impl PaintTrack {
    /* Nothing is on screen yet, so the first paint draws everything. */
    pub fn new() -> Self {
        PaintTrack {
            damage: Damage::FULL,
            painting: Damage::FULL,
            paint_gen: 1,
            painted_gen: 0,
            painted_scroll: 0,
            page_print: 0,
            chrome_print: 0,
            js_dirty: false,
            js_relayout_ms: 0,
            laid_print: None,
        }
    }
}
