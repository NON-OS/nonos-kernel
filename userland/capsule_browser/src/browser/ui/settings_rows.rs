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

use super::rect::Rect;

/// The settings page's text fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Proxy,
    Search,
}

/// What a settings control does when clicked. An index picks among the
/// choices its row offers, left to right.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    Appearance(u8),
    Network(u8),
    Field(Field),
    ProxySet,
    ProxyOff,
    Search(u8),
    SearchUse,
    ClearHistory,
    ClearDownloads,
    RemoveBookmarks,
    ReaderTheme(u8),
    Smaller,
    Larger,
    ReaderWidth(u8),
}

/// A line of text the page draws in a row's control area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Line {
    Route,
    ProxyHint,
    SearchHint,
    HistoryNote,
    DownloadsDir,
    Name,
    Version,
    Engine,
    SizeDots,
}

/// What one rect of the settings page holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Card,
    Head(&'static str),
    Label(&'static str),
    Ctl(Control),
    Line(Line),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Item {
    pub kind: Kind,
    pub rect: Rect,
}
