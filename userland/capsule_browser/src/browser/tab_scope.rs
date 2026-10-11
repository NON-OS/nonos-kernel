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

//! What of a page lives in process globals, kept per tab.
//!
//! Three things a page sets are read deep inside the engine from globals,
//! not from the page: the ways its connections leave (`net::mixnet`), the
//! network whose jar its scripts' document.cookie reads (`cookie`), and its
//! web fonts (`fonts`). The globals always hold the tab in view's. A tab
//! out of view keeps its own here, and they are swapped in for as long as
//! it steps and out again after, so a background page committing never
//! changes the route, jar or faces of the page on screen.

use crate::browser::cookie::set_page;
use crate::browser::cookie::store::page;
use crate::browser::fonts::{swap_faces, Faces};
use crate::browser::net::mixnet::{set_routes, Network, Routes, UNSET};

pub struct Scope {
    routes: Routes,
    page: Network,
    fonts: Faces,
}

impl Default for Scope {
    fn default() -> Self {
        Scope { routes: UNSET, page: Network::Nym, fonts: Faces::default() }
    }
}

/// Exchange the globals with `scope`. Twice restores both.
pub fn swap(scope: &mut Scope) {
    scope.routes = set_routes(scope.routes);
    let was = page();
    set_page(scope.page);
    scope.page = was;
    swap_faces(&mut scope.fonts);
}
