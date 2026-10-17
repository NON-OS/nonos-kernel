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

//! The parts of the window's state its hover and click geometry read,
//! standing in for the capsule's `State`, which holds syscall handles the
//! host does not have.

use alloc::vec::Vec;

use super::listing::Listing;
use super::ui::target::Target;

/// The catalogue, the window onto it, the surface's width, and the hover, so
/// a proof can show that setting it moves nothing.
pub struct State {
    pub listings: Vec<Listing>,
    pub scroll: usize,
    pub rows: usize,
    pub fb_w: u32,
    pub hover: Target,
}

impl State {
    /// Every listing, in order: the geometry reads only how many are shown
    /// and which of them is installed.
    pub fn visible(&self) -> Vec<usize> {
        (0..self.listings.len()).collect()
    }
}
