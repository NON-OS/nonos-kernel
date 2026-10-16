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

//! What a palette names: the body, gutter and syntax of the code pane, and the
//! chrome around it.

/// A full palette. Every field is an opaque ARGB colour.
#[derive(Clone, Copy)]
pub struct Theme {
    pub background: u32,
    pub foreground: u32,
    pub title: u32,
    pub muted: u32,
    pub disabled: u32,
    pub header_bg: u32,
    pub activity_bg: u32,
    pub sidebar_bg: u32,
    pub tabbar_bg: u32,
    pub tab_active_bg: u32,
    pub tab_inactive_bg: u32,
    pub row_select: u32,
    pub icon: u32,
    pub icon_active: u32,
    pub folder: u32,
    pub gutter_bg: u32,
    pub gutter_fg: u32,
    pub gutter_cur: u32,
    pub line: u32,
    pub accent: u32,
    pub caret: u32,
    pub current_line: u32,
    pub selection: u32,
    pub syn_keyword: u32,
    pub syn_string: u32,
    pub syn_comment: u32,
    pub syn_number: u32,
    pub syn_type: u32,
    pub syn_function: u32,
}
