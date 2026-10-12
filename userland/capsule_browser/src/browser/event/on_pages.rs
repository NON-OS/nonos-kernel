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

use nonos_app_skeleton::{EventOutcome, InputEvent, InputKind};

use crate::browser::omnibox::{Change, Focus};
use crate::browser::paint::pages::extent::page_scroll;
use crate::browser::settings;
use crate::browser::shell::listing::is_list;
use crate::browser::shell::{Page, Shell};
use crate::browser::tab_groups;
use crate::browser::tabs::Tabs;

use super::page_keys::{self, marked, scroll};
use super::{list_click, on_reader, rename_key::rename_key};

const WHEEL_STEP: i32 = 60;

/// Input for a page the window draws itself: a rename's or a settings
/// field's keys before the address pill sees them; the wheel and the
/// scroll keys over the start page, a list page, the settings page or the
/// reader; and clicks in the content area of a list page, the settings
/// page or the reader. A click outside the content area takes the keyboard
/// from a settings field. None for anything else, which takes the usual
/// path, so none of it reaches the tab's page hidden underneath.
pub fn on_pages(tabs: &mut Tabs, shell: &mut Shell, event: &InputEvent) -> Option<EventOutcome> {
    if let Some(out) = rename_key(shell, event) {
        return Some(marked(tabs, out, Change::Full));
    }
    if let Some(out) = settings::key(tabs, shell, event) {
        return Some(out);
    }
    let c = tabs.active().layout.content;
    let inside = c.contains(event.x, event.y);
    if event.kind == InputKind::ButtonDown && !inside && shell.settings.focus.take().is_some() {
        tabs.active_mut().mark(Change::Full);
    }
    let st = tabs.active();
    if !st.on_own {
        return None;
    }
    let at = page_scroll(shell, c.w, c.h);
    match event.kind {
        InputKind::Wheel => {
            let to = at.saturating_sub(event.delta_y.saturating_mul(WHEEL_STEP));
            Some(scroll(tabs, shell, at, to))
        }
        InputKind::KeyDown if st.ui.kbd == Focus::Page => {
            let to = page_keys::target(event.code, at, c.h)?;
            Some(scroll(tabs, shell, at, to))
        }
        InputKind::ButtonDown if inside && is_list(shell.page) => {
            tabs.active_mut().focus_page(None);
            let out = list_click::click(tabs, shell, event.x - c.x, event.y - c.y);
            Some(marked(tabs, out, Change::Full))
        }
        InputKind::ButtonDown if inside && shell.page == Page::Settings => {
            tabs.active_mut().focus_page(None);
            let out = settings::click(tabs, shell, event.x - c.x, event.y - c.y);
            Some(marked(tabs, out, Change::Full))
        }
        InputKind::ButtonDown if inside && shell.page == Page::Reader => {
            tabs.active_mut().focus_page(None);
            let out = on_reader::click(shell, c, event.x - c.x, event.y - c.y);
            Some(marked(tabs, out, Change::Full))
        }
        InputKind::ButtonDown if shell.rename.is_some() => {
            tab_groups::commit_rename(shell);
            tabs.active_mut().mark(Change::Full);
            None
        }
        _ => None,
    }
}
