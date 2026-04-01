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

use crate::display::gop::{clear_screen, get_dimensions};
use crate::display::right_panel::RightPanelLayout;
use crate::display::terminal::{draw_ascii_banner, TerminalLayout};

const BG_COLOR: u32 = 0xFF000000;

pub fn init_main_screen() {
    let (width, height) = get_dimensions();
    if width == 0 || height == 0 {
        return;
    }

    clear_screen(BG_COLOR);

    let term_layout = TerminalLayout::compute();
    draw_ascii_banner(&term_layout);
}

pub fn refresh_panels() {
    let term_layout = TerminalLayout::compute();
    let right_layout = RightPanelLayout::compute();

    redraw_terminal_content(&term_layout);
    redraw_right_content(&right_layout);
}

fn redraw_terminal_content(_layout: &TerminalLayout) {
    crate::display::log_panel::redraw_all();
}

fn redraw_right_content(_layout: &RightPanelLayout) {}
