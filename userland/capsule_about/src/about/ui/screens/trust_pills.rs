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

//! The capability pills, flowed across a card by the shared wrap: a run of
//! names is measured as the pills it draws, so height and paint agree.

use alloc::string::String;
use alloc::vec::Vec;

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::widgets::text::wrap_by;
use nonos_toolkit::widgets::{Pill, Rect, Scrolled, Tone};

use super::super::metrics::CHIP_GAP;
use super::super::mono::valid;

/// A name's pill: the dot says granted or denied and the label names the bit.
fn pill(name: &str, on: bool) -> Pill<'_> {
    Pill::new(name).tone(if on { Tone::Ok } else { Tone::Danger }).dot()
}

/// The width a run of names takes drawn as pills `CHIP_GAP` apart.
fn run_w(run: &str) -> i32 {
    let w: u32 = run.split_whitespace().map(|n| pill(n, true).size().0 + CHIP_GAP).sum();
    i32::try_from(w.saturating_sub(CHIP_GAP)).unwrap_or(i32::MAX)
}

/// The names joined by spaces, and the byte ranges of it each row holds.
fn rows(labels: &[&[u8]], w: u32) -> (String, Vec<(usize, usize)>) {
    let joined = labels.iter().map(|l| valid(l)).collect::<Vec<_>>().join(" ");
    let lines = wrap_by(&joined, i32::try_from(w).unwrap_or(i32::MAX), run_w);
    (joined, lines)
}

/// The height of `n` rows of pills, a gap apart.
fn rows_h(n: usize) -> u32 {
    let (n, h) = (n as u32, pill("", true).size().1);
    n * h + n.saturating_sub(1) * CHIP_GAP
}

/// How tall the pills for `labels` stand across `w`.
pub fn height(labels: &[&[u8]], w: u32) -> u32 {
    rows_h(rows(labels, w).1.len())
}

/// Draws the pills from `y`, through `Scrolled` above the pane; returns their height.
pub fn paint(fb: &mut PaintBuffer, x: u32, y: i32, w: u32, labels: &[&[u8]], on: bool) -> u32 {
    let (joined, lines) = rows(labels, w);
    let step = rows_h(2) - rows_h(1);
    for (i, &(start, end)) in lines.iter().enumerate() {
        let (top, mut cx) = (y + (i as u32 * step) as i32, x);
        for p in joined[start..end].split_whitespace().map(|n| pill(n, on)) {
            let at = |y| Rect { x: cx, y, w: p.size().0, h: p.size().1 };
            match u32::try_from(top) {
                Ok(t) => p.draw(fb, at(t)),
                Err(_) => p.draw(&mut Scrolled::new(fb, top.unsigned_abs()), at(0)),
            }
            cx += p.size().0 + CHIP_GAP;
        }
    }
    rows_h(lines.len())
}
