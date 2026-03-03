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

use super::super::types::Color;

pub fn apply_sgr(current: u8, sgr: usize) -> u8 {
    match sgr {
        0 => super::super::types::make_color(Color::LightGrey, Color::Black),

        30..=37 => {
            let fg = Color::from_ansi((sgr - 30) as u8);
            super::super::types::set_fg(current, fg)
        }

        40..=47 => {
            let bg = Color::from_ansi((sgr - 40) as u8);
            super::super::types::set_bg(current, bg)
        }

        90..=97 => {
            let fg = match sgr - 90 {
                0 => Color::DarkGrey,
                1 => Color::LightRed,
                2 => Color::LightGreen,
                3 => Color::Yellow,
                4 => Color::LightBlue,
                5 => Color::Pink,
                6 => Color::LightCyan,
                _ => Color::White,
            };
            super::super::types::set_fg(current, fg)
        }

        100..=107 => {
            let bg = match sgr - 100 {
                0 => Color::DarkGrey,
                1 => Color::LightRed,
                2 => Color::LightGreen,
                3 => Color::Yellow,
                4 => Color::LightBlue,
                5 => Color::Pink,
                6 => Color::LightCyan,
                _ => Color::White,
            };
            super::super::types::set_bg(current, bg)
        }

        1 => {
            let fg = current & 0x0F;
            let bright_fg = fg | 0x08;
            (current & 0xF0) | bright_fg
        }

        _ => current,
    }
}
