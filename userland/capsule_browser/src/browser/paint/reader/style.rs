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

use nonos_toolkit::font::ttf::line_height;

use super::face;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Title,
    Heading,
    Body,
    Quote,
}

pub fn px(style: Style, body: f32) -> f32 {
    match style {
        Style::Title => body * 2.2,
        Style::Heading if face::has_bold() => body * 1.25,
        Style::Heading => body * 1.45,
        Style::Body | Style::Quote => body,
    }
}

pub fn bold(style: Style) -> bool {
    matches!(style, Style::Title | Style::Heading)
}

pub fn advance(style: Style, body: f32) -> i32 {
    let lh = line_height(px(style, body));
    match style {
        Style::Body | Style::Quote => lh * 3 / 2,
        Style::Title | Style::Heading => lh * 6 / 5,
    }
}
