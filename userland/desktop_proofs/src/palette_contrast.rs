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

//! The WCAG 2.1 contrast formula in floating point, and the shell's palette for
//! every scheme the OS offers, for the palette proofs.

use crate::shell_palette::from_roles::from_roles;
use crate::shell_palette::table::ShellPalette;
use nonos_toolkit::theme::select::theme_of;
use nonos_toolkit::theme::{from_theme, SCHEMES};

/// The floor for body text, WCAG 2.1 success criterion 1.4.3 at AA.
pub const BODY: f64 = 4.5;
/// The same criterion's floor for large text.
pub const LARGE: f64 = 3.0;
/// The two wallpapers furthest apart that can show through the glass.
pub const BEHIND: [(&str, u32); 2] = [("black", 0xFF00_0000), ("white", 0xFFFF_FFFF)];

fn linear(c: u32, shift: u32) -> f64 {
    let v = ((c >> shift) & 0xff) as f64 / 255.0;
    if v <= 0.039_28 {
        v / 12.92
    } else {
        ((v + 0.055) / 1.055).powf(2.4)
    }
}

/// The contrast ratio between two opaque colours, from 1 to 21.
pub fn ratio(a: u32, b: u32) -> f64 {
    let l = |c| 0.2126 * linear(c, 16) + 0.7152 * linear(c, 8) + 0.0722 * linear(c, 0);
    let (la, lb) = (l(a), l(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

/// `top`, at its own alpha, over an opaque `under`, rounded as the shell's
/// blending rounds it.
pub fn over(under: u32, top: u32) -> u32 {
    let a = top >> 24;
    let ch = |s: u32| ((top >> s & 0xff) * a + (under >> s & 0xff) * (255 - a) + 127) / 255;
    0xFF00_0000 | ch(16) << 16 | ch(8) << 8 | ch(0)
}

/// The shell's palette for every scheme in the picker, then high contrast.
pub fn every_palette() -> Vec<(String, ShellPalette)> {
    let mut all: Vec<(String, ShellPalette)> = (0..SCHEMES.len())
        .map(|i| (format!("scheme {i}"), from_roles(&from_theme(&theme_of(i as u8, false)))))
        .collect();
    all.push(("high contrast".to_string(), from_roles(&from_theme(&theme_of(0, true)))));
    all
}
