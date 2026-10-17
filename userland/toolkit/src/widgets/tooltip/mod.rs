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

//! A tooltip: a one-line label in a small raised box by an anchor. The app
//! decides when to show it, after a pause it times with `on_tick`. `place`
//! picks the rect beside the anchor, inside the bounds it may use, and `draw`
//! paints the tooltip there over what the window already holds. It takes no
//! pointer, so it has no `hit`.

mod build;
mod geometry;
mod paint;
mod place;

pub use build::Tooltip;
