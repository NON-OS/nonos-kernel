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
    EventOutcome, InputEvent, InputKind, KEY_TAB, MOD_ALT, MOD_CTRL, MOD_SHIFT,
};

use crate::browser::tabs::Tabs;
use crate::browser::ui::tabs_geom::Strip;
use crate::browser::ui::tabs_hit::{hit, TabHit};

/// A click in the titlebar tab strip, in strip-local coordinates. A tab the
/// plus opens joins `group`.
pub fn on_tabbar(
    tabs: &mut Tabs,
    w: i32,
    h: i32,
    event: InputEvent,
    group: Option<u8>,
) -> EventOutcome {
    if event.kind != InputKind::ButtonDown {
        return EventOutcome::Idle;
    }
    let s = Strip { n: tabs.list.len(), active: tabs.active, w, h };
    let acted = match hit(&s, event.x, event.y) {
        Some(TabHit::Tab(i)) => tabs.switch(i),
        Some(TabHit::Close(i)) => tabs.close(i),
        Some(TabHit::Plus) => tabs.open(group),
        None => false,
    };
    outcome(acted)
}

/// Ctrl+T opens a tab, Ctrl+W closes the current one, Ctrl+Tab and
/// Ctrl+Shift+Tab move to the next and previous. Taken before the address
/// bar or the page sees the key; None for any other key. A tab Ctrl+T opens
/// joins `group`.
pub fn tab_key(tabs: &mut Tabs, event: &InputEvent, group: Option<u8>) -> Option<EventOutcome> {
    let ctrl = event.flags & (MOD_CTRL | MOD_ALT) == MOD_CTRL;
    if event.kind != InputKind::KeyDown || !ctrl {
        return None;
    }
    let n = tabs.list.len();
    let letter = char::from_u32(event.code).map(|c| c.to_ascii_lowercase());
    let acted = match (event.code, letter) {
        (_, Some('t')) => tabs.open(group),
        (_, Some('w')) => tabs.close(tabs.active),
        (KEY_TAB, _) if event.flags & MOD_SHIFT != 0 => tabs.switch((tabs.active + n - 1) % n),
        (KEY_TAB, _) => tabs.switch((tabs.active + 1) % n),
        _ => return None,
    };
    Some(outcome(acted))
}

fn outcome(acted: bool) -> EventOutcome {
    if acted {
        EventOutcome::Repaint
    } else {
        EventOutcome::Idle
    }
}
