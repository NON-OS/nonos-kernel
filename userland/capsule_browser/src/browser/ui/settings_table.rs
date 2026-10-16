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

use super::settings_rows::{Control as C, Field, Line};

/// One row of a section: its label, then what sits right of it.
pub enum Row {
    Options(&'static str, &'static [C]),
    Field(&'static str, Field, &'static [C], Line),
    Action(&'static str, C),
    Text(&'static str, Line),
    Size(&'static str),
}

const APPEARANCE: &[Row] =
    &[Row::Options("Theme", &[C::Appearance(2), C::Appearance(0), C::Appearance(1)])];
const NETWORK: &[Row] = &[
    Row::Options("Route", &[C::Network(0), C::Network(1), C::Network(2)]),
    Row::Text("Now", Line::Route),
    Row::Field("SOCKS5 proxy", Field::Proxy, &[C::ProxySet, C::ProxyOff], Line::ProxyHint),
];
const SEARCH: &[Row] = &[
    Row::Options("Engine", &[C::Search(0), C::Search(1)]),
    Row::Field("Template", Field::Search, &[C::SearchUse], Line::SearchHint),
];
const PRIVACY: &[Row] = &[
    Row::Text("History", Line::HistoryNote),
    Row::Action("", C::ClearHistory),
    Row::Action("Downloads", C::ClearDownloads),
    Row::Action("Bookmarks", C::RemoveBookmarks),
];
const DOWNLOADS: &[Row] = &[Row::Text("Folder", Line::DownloadsDir)];
const READER: &[Row] = &[
    Row::Options("Theme", &[C::ReaderTheme(0), C::ReaderTheme(1), C::ReaderTheme(2)]),
    Row::Size("Text size"),
    Row::Options("Width", &[C::ReaderWidth(0), C::ReaderWidth(1), C::ReaderWidth(2)]),
];
const ABOUT: &[Row] = &[
    Row::Text("Browser", Line::Name),
    Row::Text("Version", Line::Version),
    Row::Text("Engine", Line::Engine),
];

/// The page, top to bottom: each section's heading and its rows.
pub const SECTIONS: [(&str, &[Row]); 7] = [
    ("Appearance", APPEARANCE),
    ("Network", NETWORK),
    ("Search", SEARCH),
    ("Privacy & data", PRIVACY),
    ("Downloads", DOWNLOADS),
    ("Reader", READER),
    ("About", ABOUT),
];
