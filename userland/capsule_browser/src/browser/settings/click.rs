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

use nonos_app_skeleton::EventOutcome;

use crate::browser::paint::pages::extent::page_scroll;
use crate::browser::paint::settings::field;
use crate::browser::shell::Shell;
use crate::browser::tabs::Tabs;
use crate::browser::ui::settings_geom::{Control, Field, SettingsGeom};

/// A click at content-local `(x, y)` on the settings page, hit-tested
/// against the geometry it was painted with. Anything but a field takes
/// the keyboard from the fields, and anything but Remove all bookmarks
/// disarms it.
pub fn click(tabs: &mut Tabs, shell: &mut Shell, x: i32, y: i32) -> EventOutcome {
    let c = tabs.active().layout.content;
    let g = SettingsGeom::new(c.w, c.h, page_scroll(shell, c.w, c.h));
    let hit = g.hit(x, y);
    if hit != Some(Control::RemoveBookmarks) {
        shell.settings.armed = false;
    }
    match hit {
        Some(Control::Field(f)) => {
            shell.settings.focus = Some(f);
            caret_at(shell, f, &g, x);
        }
        Some(ctl) => {
            shell.settings.focus = None;
            super::act::act(tabs, shell, ctl);
        }
        None => shell.settings.focus = None,
    }
    EventOutcome::Repaint
}

/// Puts the caret of field `f` at the character boundary nearest to a
/// click at content-local `x`, where the painter drew its text.
fn caret_at(shell: &mut Shell, f: Field, g: &SettingsGeom, x: i32) {
    let Some(r) = g.rect(Control::Field(f)) else { return };
    let ed = shell.settings.field(f);
    let b = field::text_box(r);
    let at = field::nearest(&ed.text, x - b.x + field::offset(ed, b.w));
    (ed.caret, ed.anchor) = (at, at);
}
