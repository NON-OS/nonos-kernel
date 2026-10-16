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

use crate::browser::paint::tokens;
use crate::browser::shell::kept::{Appearance, MAX_SIZE};
use crate::browser::shell::{store, Shell};
use crate::browser::tabs::Tabs;
use crate::browser::ui::settings_geom::Control;

/// Does what `ctl` stands for. Appearance and the reader's defaults are
/// saved with the bookmarks at once; a new appearance repaints every tab
/// as the event returns (`Browser::retheme`).
pub(super) fn act(tabs: &mut Tabs, shell: &mut Shell, ctl: Control) {
    match ctl {
        Control::Appearance(i) => {
            shell.appearance = Appearance::from_byte(i);
            tokens::set_mode(shell.appearance);
        }
        Control::Network(i) => return super::net_act::choose(tabs, i),
        Control::ProxySet => return super::net_act::set_proxy(tabs, shell),
        Control::ProxyOff => return super::net_act::proxy_off(tabs, shell),
        Control::Search(i) => return super::search_act::pick(tabs, shell, i),
        Control::SearchUse => return super::search_act::apply(tabs, shell),
        Control::ClearHistory | Control::ClearDownloads | Control::RemoveBookmarks => {
            return super::privacy::clear(shell, ctl);
        }
        Control::ReaderTheme(i) => shell.reader.theme = i,
        Control::Smaller => shell.reader.size = shell.reader.size.saturating_sub(1),
        Control::Larger => shell.reader.size = (shell.reader.size + 1).min(MAX_SIZE),
        Control::ReaderWidth(i) => shell.reader.width = i,
        Control::Field(_) => return,
    }
    store::sync(shell);
}
