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

use nonos_app_skeleton::{
    EventOutcome, KEY_DOWN, KEY_END, KEY_HOME, KEY_PAGE_DOWN, KEY_PAGE_UP, KEY_UP,
};

use crate::browser::omnibox::Change;
use crate::browser::paint::pages::extent::page_scroll;
use crate::browser::shell::Shell;
use crate::browser::tabs::Tabs;

const LINE: i32 = 40;

/// Where a scroll key moves a page the window draws itself, from `at` in a
/// view `view_h` tall, before it is held to the page. None for other keys.
pub(super) fn target(code: u32, at: i32, view_h: i32) -> Option<i32> {
    let page = view_h - LINE;
    Some(match code {
        KEY_UP => at - LINE,
        KEY_DOWN => at + LINE,
        KEY_PAGE_UP => at - page,
        KEY_PAGE_DOWN | 0x20 => at + page,
        KEY_HOME => 0,
        KEY_END => i32::MAX / 2,
        _ => return None,
    })
}

/* Moves the page from `at` to `to`, held to how far it can go. A notch or
 * key at either end changes nothing and draws nothing. */
pub(super) fn scroll(tabs: &mut Tabs, shell: &mut Shell, at: i32, to: i32) -> EventOutcome {
    let c = tabs.active().layout.content;
    shell.page_scroll = to;
    shell.page_scroll = page_scroll(shell, c.w, c.h);
    match shell.page_scroll == at {
        true => EventOutcome::Idle,
        false => marked(tabs, EventOutcome::Repaint, Change::Page),
    }
}

pub(super) fn marked(tabs: &mut Tabs, out: EventOutcome, change: Change) -> EventOutcome {
    if out == EventOutcome::Repaint {
        tabs.active_mut().mark(change);
    }
    out
}
