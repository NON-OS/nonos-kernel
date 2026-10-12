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
use alloc::string::String;

use nonos_app_skeleton::{measure_ttf, PaintBuffer};

use super::page::{text, PX};
use crate::browser::paint::tokens::palette;
use crate::browser::settings::network_line;
use crate::browser::shell::kept::MAX_SIZE;
use crate::browser::shell::Shell;
use crate::browser::state::State;
use crate::browser::ui::fit::truncate_to;
use crate::browser::ui::rect::Rect;
use crate::browser::ui::settings_geom::Line;

const DOT: i32 = 8;
const PROXY_HINT: &str = "A SOCKS5 proxy as host:port. It carries Direct requests only.";
const SEARCH_HINT: &str = "An address with %s where the search words go.";
const ENGINE: &str = "Own HTML, CSS and layout engine; QuickJS runs page scripts";

/// The line `l` in `r`, cut to its width; a field's line says what the
/// field last refused, in the error colour, until it is typed in again.
pub fn paint(fb: &mut PaintBuffer, state: &State, shell: &Shell, l: Line, r: Rect) {
    let p = palette();
    let (s, ink): (String, u32) = match l {
        Line::SizeDots => return dots(fb, shell.reader.size, r),
        Line::Route => (network_line(state), p.ink2),
        Line::ProxyHint => hint(shell.settings.proxy_err, PROXY_HINT),
        Line::SearchHint => hint(shell.settings.search_err, SEARCH_HINT),
        Line::HistoryNote => (String::from("History clears at shutdown"), p.ink2),
        Line::DownloadsDir => (String::from("Saved files go to /home/Downloads"), p.ink2),
        Line::Name => (String::from("N\u{d8}NOS Browser"), p.ink),
        Line::Version => (format!("Version {}", env!("CARGO_PKG_VERSION")), p.ink2),
        Line::Engine => (String::from(ENGINE), p.ink2),
    };
    let s = truncate_to(&s, r.w, |t| measure_ttf(t, PX));
    text(fb, r, &s, ink, PX);
}

fn hint(err: Option<&'static str>, fallback: &str) -> (String, u32) {
    match err {
        Some(why) => (String::from(why), palette().err),
        None => (String::from(fallback), palette().muted),
    }
}

/* One dot per text size step, lit up to the one in force. */
fn dots(fb: &mut PaintBuffer, size: u8, r: Rect) {
    let steps = MAX_SIZE as i32 + 1;
    let step = r.w / (steps + 1);
    let cy = r.y + r.h / 2;
    for i in 0..steps {
        let on = i <= size as i32;
        let x = r.x + step * (i + 1) - DOT / 2;
        let argb = if on { palette().accent } else { palette().edge };
        let (d, rad) = (DOT as u32, DOT as u32 / 2);
        fb.fill_round(x as u32, (cy - DOT / 2) as u32, d, d, rad, argb);
    }
}
