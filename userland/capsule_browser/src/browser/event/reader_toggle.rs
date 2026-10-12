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

use crate::browser::reader::extract::extract;
use crate::browser::shell::{Page, Shell};
use crate::browser::state::{State, View};

/// True when the tab in view shows a parsed page the reader can extract.
pub fn ready(state: &State) -> bool {
    state.view == View::Page && state.page_dom.is_some()
}

/// The toolbar Reader button and the sidebar Reading View row: leaves the
/// reader when it is showing, else opens it on the tab's page, the site
/// named by the address in the pill.
pub(super) fn toggle(state: &State, shell: &mut Shell) -> EventOutcome {
    if shell.page == Page::Reader {
        shell.show(Page::Web);
        return EventOutcome::Repaint;
    }
    match state.page_dom.as_ref().filter(|_| ready(state)) {
        Some(dom) => {
            shell.article = Some(extract(dom, &state.ui.current_url));
            shell.show(Page::Reader);
            EventOutcome::Repaint
        }
        None => EventOutcome::Idle,
    }
}
