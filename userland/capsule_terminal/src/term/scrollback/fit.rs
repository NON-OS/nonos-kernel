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

use nonos_vt::Palette;

use super::types::Scrollback;
use crate::term::theme::types::Theme;

/// The colour bits of an ARGB value; the screen's palette carries no alpha.
const RGB: u32 = 0x00FF_FFFF;

impl Scrollback {
    /// Match the screen to the window. A resize re-wraps what is there.
    /// True when the size in cells changed.
    pub fn fit(&mut self, cols: usize, rows: usize, cell_w: u32, cell_h: u32) -> bool {
        let changed = (cols, rows) != (self.vt.cols(), self.vt.rows());
        self.vt.resize(cols, rows);
        self.vt.set_cell_pixels(
            cell_w.min(u16::MAX as u32) as u16,
            cell_h.min(u16::MAX as u32) as u16,
        );
        changed
    }

    /// Program colours start from the window's theme. Only a change of
    /// `key` resets them, so a colour a program set survives a repaint. Under
    /// System the key carries the OS theme's revision, so a theme chosen in
    /// Settings resets them too.
    pub fn follow_theme(&mut self, key: (u16, u32), t: &Theme, ansi: &[u32; 16]) {
        if self.theme_of == Some(key) {
            return;
        }
        let mut p = Palette::xterm();
        for (slot, &c) in p.colors[..16].iter_mut().zip(ansi) {
            *slot = c & RGB;
        }
        p.fg = t.fg & RGB;
        p.bg = t.bg & RGB;
        p.cursor = t.accent & RGB;
        self.vt.set_theme(p);
        self.theme_of = Some(key);
    }
}
