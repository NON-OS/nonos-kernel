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

use nonos_app_skeleton::PaintBuffer;

use super::block_chrome::draw_block_chrome;
use super::draw_input_line::draw_input_line;
use super::fetch::draw_fetch;
use super::footer::draw_footer;
use super::geometry::geometry;
use super::header::draw_header;
use super::rail_left;
use super::vt::{draw_find_bar, draw_vt, Area, Frame, Rows};
use crate::layout::Layout;
use crate::palette::{Index, Palette};
use crate::rail::Rail;
use crate::term::prefs::types::Project;
use crate::term::state::State;
use crate::term::theme::types::Theme;

/// The splash's swatches: red through white, then bright black.
const SWATCHES: core::ops::Range<usize> = 1..9;

pub fn paint_tabs(
    tabs: &[State],
    active: usize,
    fb: &mut PaintBuffer,
    t: &Theme,
    font_scale: u32,
    rail: &Rail,
    projects: &[Project],
    monitor: bool,
    scroll: u32,
    pal: &Palette,
    rail_open: bool,
) -> Layout {
    let l = paint(&tabs[active], fb, t, font_scale, rail_open);
    if l.left_rail.w > 0 {
        rail_left::draw(fb, l.left_rail, tabs, active, projects, rail, monitor, scroll, t);
    }
    if pal.open {
        let ix = Index::build(tabs, active, projects);
        super::palette::draw(fb, l.body, pal, &ix, t);
    }
    l
}

pub fn paint(
    state: &State,
    fb: &mut PaintBuffer,
    t: &Theme,
    font_scale: u32,
    rail_open: bool,
) -> Layout {
    fb.clear(t.bg);
    draw_header(state, fb, t);
    let (l, m, chrome) = geometry(fb, font_scale, rail_open);
    let text_x = l.body.x + chrome.text_left;
    let text_r = (l.body.x + l.body.w).saturating_sub(chrome.text_left);
    let vt = &state.scrollback.vt;
    /*
     * A program in the foreground, or on the alternate screen, owns the
     * whole body and is drawn as its screen; the prompt returns at its end.
     */
    let owned = vt.alt_active() || state.fg_running;
    let bottom = if owned { l.footer.y } else { l.input.y };
    let area = Area { x: text_x, y: l.body.y, max_x: text_r, max_y: bottom };
    let f = Frame { vt, area, m, t };
    if owned {
        draw_vt(&f, fb, Rows::Screen, state.shade());
    } else if state.fresh {
        draw_fetch(fb, text_x, l.body.y, text_r, t, &vt.palette().colors[SWATCHES]);
    } else {
        let rows = Rows::Shell { rows: (l.body.h / m.lh.max(1)) as usize, back: vt.view_offset() };
        draw_block_chrome(state, fb, &f.area, rows.first(vt), &m, t);
        draw_vt(&f, fb, rows, state.shade());
    }
    if let Some(find) = &state.find {
        draw_find_bar(find, fb, l.input, m, t);
    } else if !owned {
        draw_input_line(state, fb, l.input, m, t);
    }
    draw_footer(fb, t);
    l
}
