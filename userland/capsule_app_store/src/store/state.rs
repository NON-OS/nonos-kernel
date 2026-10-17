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

//! What the window is showing.

pub use super::tab::{Tab, TABS};

use alloc::vec::Vec;

use nonos_toolkit::widgets::Pointer;

use super::listing::Listing;
use super::ui::target::Target;

pub struct State {
    pub listings: Vec<Listing>,
    pub tab: Tab,
    pub cursor: usize,
    pub scroll: usize,
    pub rows: usize,
    pub fb_w: u32,
    pub fb_h: u32,
    /// Set when the catalogue could not be read: why, one line per `\n`.
    pub trouble: Option<Vec<u8>>,
    /// What the last install request was answered with, shown until the next
    /// one.
    pub asked: Option<super::install::Asked>,
    pub search: super::search::Search,
    /// The market's port as the last catalogue fetch found it, zero for none.
    /// Each listing's answers are asked of this port on a tick, never on a
    /// key or a click (`fill`).
    pub port: u32,
    /// The catalogue has been asked for. The window opens without asking,
    /// so its first frame never waits on the market.
    pub loaded: bool,
    /// This machine's memory and where a tier's model is kept on this boot,
    /// read with the catalogue: which tier cards fit (`tier_fit`).
    pub memory: Option<u64>,
    pub room: crate::need::Room,
    /// The network a tier's download would leave by now, read with the
    /// catalogue and on `r`.
    pub route: crate::net::Route,
    /// What the model fetcher last answered of the download it runs for a
    /// tier's install, and when it may be asked again (`fetch_status`).
    pub fetch: Option<crate::status_wire::Status>,
    pub fetch_at_ms: i64,
    /// The pointer over the content, fed by every move, press and release.
    pub pointer: Pointer,
    /// What is under the pointer, so a move repaints only when it changes.
    pub hover: Target,
}
