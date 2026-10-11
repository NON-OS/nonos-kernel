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

use alloc::string::String;
use alloc::vec::Vec;

pub use super::pill_row::{badge_w, row};
use crate::browser::paint::pages::group_pills;
use crate::browser::shell::downloads::counts;
use crate::browser::shell::route::FILTERS;
use crate::browser::shell::{Page, Shell};

pub const PX: f32 = 17.0;
pub const PAD: i32 = 16;
pub const BADGE_GAP: i32 = 8;
pub const BADGE_PAD: i32 = 8;
pub const DOT: i32 = 10;
pub const DOT_GAP: i32 = 8;
const DOWNLOADS: [&str; 3] = ["All", "Saved", "Failed"];

/// What a click on a pill does: picks History's or Downloads' filter
/// `i`, filters the Tabs page to a group (every tab for None), or adds one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pick {
    Filter(u8),
    Group(Option<u8>),
    NewGroup,
}

/// One filter pill: its label, the count in its badge if it has one, and
/// whether it is the filter in force.
pub struct Pill {
    pub label: String,
    pub count: Option<usize>,
    pub on: bool,
    pub dot: Option<u32>,
    pub dim: bool,
    pub pick: Pick,
}

/// The filter pills of the page the window shows; none for a page without.
pub fn specs(shell: &Shell) -> Vec<Pill> {
    let (labels, on, tally): (&[&str], u8, Option<[usize; 3]>) = match shell.page {
        Page::History => (&FILTERS, shell.hist_filter, None),
        Page::Downloads => (&DOWNLOADS, shell.dl_filter, Some(counts(&shell.downloads))),
        Page::Tabs => return group_pills::specs(shell),
        _ => return Vec::new(),
    };
    let pill = |(i, &label): (usize, &&str)| Pill {
        label: String::from(label),
        count: tally.map(|c| c[i]),
        on: i == on as usize,
        dot: None,
        dim: false,
        pick: Pick::Filter(i as u8),
    };
    labels.iter().enumerate().map(pill).collect()
}
