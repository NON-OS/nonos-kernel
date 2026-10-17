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
use nonos_toolkit::theme::roles;

use crate::clock::says::NOT_SET;
use crate::clock::state::State;
use crate::clock::tabs::Tab;
use crate::clock::{fmt, paint_analog, paint_settime, paint_stopwatch, paint_tabbar, paint_timer};

pub fn paint(state: &State, fb: &mut PaintBuffer) {
    fb.clear(roles().bg.argb());
    match state.tab {
        Tab::Clock => paint_clock(state, fb),
        Tab::Stopwatch => paint_stopwatch::paint(state, fb),
        Tab::Timer => paint_timer::paint(state, fb),
        Tab::Set => paint_settime::paint(state, fb),
    }
    paint_tabbar::paint(state, fb);
}

fn paint_clock(state: &State, fb: &mut PaintBuffer) {
    let theme = roles();
    /* Drawn from no reading the face would show midnight of year zero. */
    if !state.clock_ok {
        fb.text(40, 122, NOT_SET, theme.danger.argb());
        return;
    }
    let (r, muted) = (&state.rtc, theme.muted.argb());
    let hms = fmt::hms(r.hour, r.minute, r.second);
    fb.text_scaled(36, 72, &hms, theme.text.argb(), 4);
    let wd = fmt::weekday(r.year, r.month, r.day);
    fb.text(40, 122, wd.as_bytes(), muted);
    let mon = fmt::month_name(r.month);
    fb.text(40, 142, mon.as_bytes(), muted);
    let dd = fmt::two(r.day);
    fb.text(84, 142, &dd, muted);
    let yr = fmt::year4(r.year);
    fb.text(120, 142, &yr, muted);
    paint_analog::paint(state, fb, 180, 300, 84);
}
