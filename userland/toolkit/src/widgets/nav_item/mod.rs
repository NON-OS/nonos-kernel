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

//! A navigation item: one entry of a sidebar, a label on a rounded body that
//! fills the width it is given. `active` marks the page on show; it draws
//! on an accent wash with an accent edge. `State::selected` is ignored, since
//! `active` says the same. There is no icon yet; icons come with
//! `IconButton`.

mod build;
mod geometry;
mod paint;

pub use build::NavItem;
