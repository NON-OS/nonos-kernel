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
use alloc::format;
use alloc::string::String;

use nonos_app_skeleton::EventOutcome;

use super::geometry::{action_at, Action};
use crate::browser::net::mixnet;
use crate::browser::omnibox::Change;
use crate::browser::paint::tokens;
use crate::browser::shell::kept::Appearance;
use crate::browser::shell::{store, Shell};
use crate::browser::state::State;

/// Handle a click while the panel is open. A click on empty space, or anywhere
/// outside the panel, closes it.
///
/// Choosing a network changes where the next request goes and nothing else:
/// the route itself is taken when that request starts, so a page already
/// loading finishes on the network it started on. Switching the appearance
/// takes effect at once and is saved with the bookmarks.
pub fn on_click(state: &mut State, shell: &mut Shell, x: i32, y: i32) -> EventOutcome {
    match action_at(x, y, state.layout.toolbar.w) {
        Action::Choose(net) => {
            mixnet::choose(net);
            state.settings_open = false;
            state.tell(format!("{} from the next request.", net.label()));
        }
        Action::Proxy if state.proxy.is_some() => {
            state.proxy = None;
            state.settings_open = false;
            state.tell(String::from("SOCKS5 proxy off."));
        }
        Action::Proxy => {
            state.settings_open = false;
            state.ui.omnibox.set("proxy socks5://");
            state.focus_omnibox();
            state.ui.omnibox.caret_to_end();
            state.fit_text();
            state.tell(String::from("Type the proxy host:port, then press Enter."));
        }
        Action::Appearance => {
            shell.appearance = shell.appearance.toggled();
            tokens::set_dark(shell.appearance == Appearance::Dark);
            store::sync(shell);
        }
        Action::Close => state.settings_open = false,
        Action::Ignore => {}
    }
    /* The panel sits over the page: whatever changed, redraw it all. */
    state.mark(Change::Full);
    EventOutcome::Repaint
}
