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
//! Where each control sits. The painters draw there and the click and hover
//! tests read the same rectangles, so a click lands on what was drawn.

use nonos_toolkit::widgets::rect::contains;
use nonos_toolkit::widgets::Rect;

use crate::clock::tabs::{bar, strip, Tab};

/// What the pointer can be over: a tab, or the `n`th button of the tab shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Tab(usize),
    Key(usize),
}

const fn at(x: u32, y: u32, w: u32, h: u32) -> Rect {
    Rect { x, y, w, h }
}

/// Start or stop, then reset.
const STOPWATCH: [Rect; 2] = [at(40, 300, 130, 46), at(190, 300, 130, 46)];
/// The 1, 5 and 10 minute presets, then start or pause, then reset.
const TIMER: [Rect; 5] = [
    at(40, 250, 80, 40),
    at(140, 250, 80, 40),
    at(240, 250, 80, 40),
    at(40, 320, 130, 46),
    at(190, 320, 130, 46),
];
/// Hour down and up, minute down and up, then apply.
const SET: [Rect; 5] = [
    at(40, 210, 68, 48),
    at(118, 210, 68, 48),
    at(202, 210, 68, 48),
    at(280, 210, 68, 48),
    at(40, 300, 280, 48),
];

/// The buttons the tab `t` shows, in the order their `Key` numbers them.
pub fn keys(t: Tab) -> &'static [Rect] {
    match t {
        Tab::Clock => &[],
        Tab::Stopwatch => &STOPWATCH,
        Tab::Timer => &TIMER,
        Tab::Set => &SET,
    }
}

/// What is at `(x, y)` while `t` is shown in a window `width` wide.
pub fn target_at(t: Tab, width: u32, x: i32, y: i32) -> Option<Target> {
    if let Some(i) = strip(t).hit(bar(width), x, y) {
        return Some(Target::Tab(i));
    }
    keys(t).iter().position(|&k| contains(k, x, y)).map(Target::Key)
}
