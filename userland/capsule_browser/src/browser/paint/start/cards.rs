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

use alloc::format;

use nonos_app_skeleton::{measure_ttf, PaintBuffer};

use crate::browser::paint::tokens::palette;
use crate::browser::paint::toolbar::route_label;
use crate::browser::shell::dl_line::{count_line, status_line};
use crate::browser::shell::visits::top_sites;
use crate::browser::shell::Shell;
use crate::browser::state::State;
use crate::browser::ui::start_geom::StartGeom;

use super::card::{card, endpoint, line, FIRST, LINE_PX, PAD, STEP};

const TOP_SITES: usize = 5;

/// Frequently visited, Network and This session, side by side or stacked.
/// This session counts tabs, visits and downloads, the newest download's
/// line under them.
pub fn paint(state: &State, shell: &Shell, g: &StartGeom, fb: &mut PaintBuffer) {
    let [freq, net, session] = g.cards;
    card(fb, freq, "Frequently visited");
    let top = top_sites(&shell.visits, TOP_SITES);
    if top.is_empty() {
        line(fb, freq, 0, "Sites you visit this session", palette().muted);
        line(fb, freq, 1, "appear here.", palette().muted);
    }
    for (i, (host, n)) in top.iter().enumerate() {
        line(fb, freq, i, host, palette().ink2);
        let count = format!("{}", n);
        let cx = freq.right() - PAD - measure_ttf(&count, LINE_PX);
        fb.text_ttf(cx, freq.y + FIRST + i as i32 * STEP, &count, palette().muted, LINE_PX);
    }
    card(fb, net, "Network");
    let (name, _, ink) = route_label(state);
    line(fb, net, 0, name, ink);
    line(fb, net, 1, &endpoint(state), palette().muted);
    card(fb, session, "This session");
    line(fb, session, 0, &format!("Open tabs: {}", shell.cards.len()), palette().ink2);
    line(fb, session, 1, &format!("Pages visited: {}", shell.visits.len()), palette().ink2);
    line(fb, session, 2, &count_line(&shell.downloads), palette().ink2);
    let last = shell.downloads.last().map(status_line);
    if let Some(s) = &last {
        line(fb, session, 3, s, palette().muted);
    }
    line(fb, session, 3 + last.is_some() as usize, "History clears at shutdown", palette().muted);
}
