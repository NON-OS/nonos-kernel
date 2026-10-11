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

use alloc::vec::Vec;

use crate::browser::shell::cards::TabCard;
use crate::browser::shell::site_label;
use crate::browser::state::{State, View};
use crate::browser::tabs::Tabs;

/* The window's tabs as the Tabs page, the sidebar and the start page
 * draw them. A tab with nothing loaded is a new tab. */
pub(super) fn cards(tabs: &Tabs) -> Vec<TabCard> {
    let card = |(i, s): (usize, &alloc::boxed::Box<State>)| {
        let (title, host) = match s.view {
            View::Home => ("New tab".into(), "Start page".into()),
            View::Page => {
                let url = &s.ui.current_url;
                (site_label::title(&s.title, url), site_label::site(url))
            }
        };
        TabCard { title, host, group: s.group, active: i == tabs.active }
    };
    tabs.list.iter().enumerate().map(card).collect()
}
