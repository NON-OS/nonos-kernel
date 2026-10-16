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

//! One ink a readability proof reads, and how it is read back.

use nonos_toolkit::widgets::State;

use super::canvas::Canvas;
use super::hide::Hide;
use super::mask::Masked;
use super::widget::Widget;
use crate::wcag::ratio;

/// What an ink is read against: another widget drawn without it, or the same
/// widget drawn with one mark hidden, so the ground under the ink is exact.
pub(crate) enum Off<W> {
    Widget(W),
    Hide(Hide),
}

/// One ink to read: what it is, the widget with it, what it is read against,
/// and its floor while live. colours.md sets no floor for `disabled`, so a
/// disabled ink need only be drawn and differ from what is under it. A mark
/// under `NONE` has no floor at all: it need only be visible while live.
pub(crate) struct Read<W> {
    pub(crate) what: &'static str,
    pub(crate) on: W,
    pub(crate) off: Off<W>,
    pub(crate) floor: f64,
}

/// The floor of a mark colours.md sets none for.
pub(crate) const NONE: f64 = 1.0;

/// The ink ratio `read` reaches in state `st`, drawn at its own size over
/// `ground`.
pub(crate) fn reach<W: Widget>(read: &Read<W>, st: State, ground: u32) -> f64 {
    let on = read.on.with(st);
    let at = on.read_box();
    let base = Canvas::new(at, ground);
    let lit = base.clone().painted(|fb| on.paint(fb, at));
    let dark = match read.off {
        Off::Widget(w) => base.painted(|fb| w.with(st).paint(fb, at)),
        Off::Hide(hide) => base.painted(|fb| on.paint(&mut Masked { fb, hide, rounds: 0 }, at)),
    };
    ink_ratio(&lit, &dark).unwrap_or(1.0)
}

/// The highest contrast between a pixel of `on` and the same pixel of `off`,
/// over the pixels where they differ: the ink at full cover against the
/// ground under it. None when nothing differs.
pub(crate) fn ink_ratio(on: &Canvas, off: &Canvas) -> Option<f64> {
    let each = on.diff(off).into_iter().map(|(x, y)| ratio(on.get(x, y), off.get(x, y)));
    each.reduce(f64::max)
}
