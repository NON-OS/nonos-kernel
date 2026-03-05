// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use uefi::proto::console::text::Color;

#[derive(Clone, Copy, Debug)]
pub struct Theme {
    pub bg: Color,
    pub info: Color,
    pub ok: Color,
    pub warn: Color,
    pub err: Color,
    pub title: Color,
    pub text: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            bg: Color::Black,
            info: Color::LightGray,
            ok: Color::LightGreen,
            warn: Color::Yellow,
            err: Color::LightRed,
            title: Color::LightCyan,
            text: Color::White,
        }
    }
}

impl Theme {
    pub fn new(
        bg: Color,
        info: Color,
        ok: Color,
        warn: Color,
        err: Color,
        title: Color,
        text: Color,
    ) -> Self {
        Self {
            bg,
            info,
            ok,
            warn,
            err,
            title,
            text,
        }
    }

    pub fn high_contrast() -> Self {
        Self {
            bg: Color::Black,
            info: Color::White,
            ok: Color::LightGreen,
            warn: Color::Yellow,
            err: Color::Red,
            title: Color::Cyan,
            text: Color::White,
        }
    }

    pub fn monochrome() -> Self {
        Self {
            bg: Color::Black,
            info: Color::LightGray,
            ok: Color::LightGray,
            warn: Color::White,
            err: Color::White,
            title: Color::White,
            text: Color::LightGray,
        }
    }
}
