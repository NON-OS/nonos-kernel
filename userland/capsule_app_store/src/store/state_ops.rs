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

//! Moving through the catalogue.

use alloc::vec::Vec;

use super::model_weights::MODEL_WEIGHTS;
use super::state::{State, Tab};
use super::tier_fit::{order, shown};

impl State {
    pub fn new() -> State {
        State {
            listings: Vec::new(),
            tab: Tab::All,
            cursor: 0,
            scroll: 0,
            rows: 1,
            fb_w: 0,
            fb_h: 0,
            trouble: None,
            asked: None,
            search: super::search::Search::default(),
            port: 0,
            loaded: false,
            memory: None,
            room: crate::need::Room::Memory,
            route: crate::net::Route::Down(""),
            fetch: None,
            fetch_at_ms: 0,
            pointer: nonos_toolkit::widgets::Pointer::new(),
            hover: super::ui::target::Target::None,
        }
    }

    /// Indices into `listings` that the current tab and the search show,
    /// less the Qwen tiers that do not fit this machine, the tiers last and
    /// smallest first (`tier_fit`). A description counts once the market
    /// has said it (`fill`); the filter itself reads only what is held, so
    /// typing asks the market nothing.
    pub fn visible(&self) -> Vec<usize> {
        let mut out: Vec<usize> = self.matching().filter(|&i| self.fits(i)).collect();
        out.sort_by_key(|&i| order(&self.listings[i].id, MODEL_WEIGHTS));
        out
    }

    /// How many tiers the tab and the search would show but this machine
    /// has too little memory for.
    pub fn hidden(&self) -> usize {
        self.matching().filter(|&i| !self.fits(i)).count()
    }

    fn matching(&self) -> impl Iterator<Item = usize> + '_ {
        self.listings.iter().enumerate().filter_map(|(i, l)| {
            let description = l.known.detail.as_ref().map(|d| d.description.as_slice());
            let kept = self.tab.accepts(l.source) && self.search.matches(&l.name, description);
            kept.then_some(i)
        })
    }

    /// What the fetcher said of `l`'s download, when `l` is the tier
    /// installing and the answer is its: the tier whose files sum to it.
    /// Another listing whose install or uninstall is moving, which a queued
    /// one waits behind: the personality runs one installer at a time.
    pub fn ahead_of(&self, l: &super::listing::Listing) -> Option<&super::listing::Listing> {
        use super::progress::Progress;
        self.listings
            .iter()
            .find(|o| o.id != l.id && matches!(o.progress, Progress::Installing | Progress::Removing))
    }

    pub fn fetch_of(&self, l: &super::listing::Listing) -> Option<crate::status_wire::Status> {
        let s = self.fetch?;
        let tier = super::tier_fit::tier_of(&l.id)?;
        // Starting has no total yet; one install runs at a time, so it is
        // the tier installing.
        let mine = s.stage == crate::status_wire::STARTING
            || super::tier_fit::weight(tier, MODEL_WEIGHTS) == Some(s.total);
        (l.progress == super::progress::Progress::Installing && mine).then_some(s)
    }

    fn fits(&self, i: usize) -> bool {
        shown(&self.listings[i].id, MODEL_WEIGHTS, self.memory, self.room)
    }
}
