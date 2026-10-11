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

//! The settings panel behind the menu button. It says which network requests
//! leave through, lets the reader choose Direct, Nym or Anyone for the next
//! request, keeps the manual SOCKS5 proxy for the direct network (focusing the
//! address bar with the command prefix), and names the search it falls back to.

mod click;
mod geometry;
mod panel;
mod search;

pub use click::on_click;
pub use panel::paint;
pub use search::SEARCH_TEMPLATE;
