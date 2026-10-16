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
use nonos_toolkit::font::ttf::line_height;
use nonos_toolkit::theme::roles;

use crate::pm::state::Ring;

use super::metrics::{BODY_PX, CARD_LINE_GAP, INSP_SECTION_GAP, SPARK_H};
use super::{spark, text};

/// How far `paint` moves down: two panels, each a caption and a plot.
pub fn height() -> u32 {
    2 * (line_height(BODY_PX).max(1) as u32 + CARD_LINE_GAP + SPARK_H + INSP_SECTION_GAP)
}

// Two trend panels over the same per-pid ring. A single sample has no shape and
// a flat line would read as a real idle stretch, so the caption says
// "collecting" and the plot stays empty until two points can be joined.
// A process that genuinely uses nothing plots flat along the baseline and is
// indistinguishable from a panel that failed to draw. That is the state most
// processes on an idle machine are in, so it is worth its own word: the
// caption says so and the flat line is drawn where a reader can see it, rather
// than hidden under the axis.
pub fn paint(fb: &mut PaintBuffer, x: u32, y: u32, w: u32, ring: Option<&Ring>) -> u32 {
    let live = ring.map(|r| r.len() >= 2).unwrap_or(false);
    let flat_cpu = live && ring.map(|r| (0..r.len()).all(|i| r.cpu_at(i) == 0)).unwrap_or(false);
    let flat_mem = live && ring.map(|r| (0..r.len()).all(|i| r.mem_at(i) == 0)).unwrap_or(false);

    let mut y = head(fb, x, y, w, b"CPU", live, flat_cpu);
    plot(fb, x, y, w, ring.filter(|_| live), true, flat_cpu);
    y += SPARK_H + INSP_SECTION_GAP;
    y = head(fb, x, y, w, b"Memory", live, flat_mem);
    plot(fb, x, y, w, ring.filter(|_| live), false, flat_mem);
    y + SPARK_H + INSP_SECTION_GAP
}

fn head(fb: &mut PaintBuffer, x: u32, y: u32, w: u32, label: &[u8], live: bool, flat: bool) -> u32 {
    let muted = roles().muted;
    text::left(fb, x, y, label, muted, BODY_PX);
    let tail: &[u8] = match (live, flat) {
        (false, _) => b"collecting",
        (true, true) => b"idle, last 60s",
        (true, false) => b"last 60s",
    };
    text::right(fb, x + w, y, tail, muted, BODY_PX);
    y + line_height(BODY_PX).max(1) as u32 + CARD_LINE_GAP
}

// The baseline is drawn either way, so an empty panel still reads as a plot
// waiting for data rather than as a gap in the pane. A flat series is drawn
// one pixel clear of the axis and in the series colour, so a reader sees a
// measured zero rather than an axis with nothing on it.
fn plot(fb: &mut PaintBuffer, x: u32, y: u32, w: u32, ring: Option<&Ring>, cpu: bool, flat: bool) {
    let r = roles();
    fb.fill_rect(x, y + SPARK_H.saturating_sub(1), w, 1, r.border_strong.argb());
    let Some(ring) = ring else {
        return;
    };
    let c = if cpu { r.accent } else { r.ok };
    if flat {
        fb.fill_rect(x, y + SPARK_H.saturating_sub(2), w, 1, c.argb());
        return;
    }
    if cpu {
        spark::cpu(fb, x, y, w, SPARK_H, ring, c);
    } else {
        spark::mem(fb, x, y, w, SPARK_H, ring, c);
    }
}
