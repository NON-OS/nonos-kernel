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
use nonos_toolkit::widgets::{Rect, Tabs};

#[derive(Clone, Copy, PartialEq)]
pub enum Tab {
    Clock,
    Stopwatch,
    Timer,
    Set,
}

pub const BAR_H: u32 = 32;
pub const BAR_TOP: u32 = 28;

/// The tabs' names, in the order `all` gives them.
pub const LABELS: [&str; 4] = ["Clock", "Stopwatch", "Timer", "Set"];

pub fn all() -> [Tab; 4] {
    [Tab::Clock, Tab::Stopwatch, Tab::Timer, Tab::Set]
}

/// Where `t` sits in `all`.
pub fn index(t: Tab) -> usize {
    all().iter().position(|&a| a == t).unwrap_or(0)
}

/// The tab bar across a window `width` wide, and the strip drawn in it.
pub fn bar(width: u32) -> Rect {
    Rect { x: 0, y: BAR_TOP, w: width, h: BAR_H }
}

pub fn strip(t: Tab) -> Tabs<'static> {
    Tabs::new(&LABELS, index(t))
}
