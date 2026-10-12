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

use super::toolbar_geom::ToolbarGeom;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    Back,
    Fwd,
    Reload,
    Home,
    Pill,
    Route,
    Reader,
    Star,
    Tabs,
    Sidebar,
}

/// The toolbar part under `(x, y)`; the route badge wins over the pill it sits in.
pub fn hit(g: &ToolbarGeom, x: i32, y: i32) -> Option<Part> {
    let parts = [
        (g.back, Part::Back),
        (g.fwd, Part::Fwd),
        (g.reload, Part::Reload),
        (g.home, Part::Home),
        (g.route, Part::Route),
        (g.pill, Part::Pill),
        (g.reader, Part::Reader),
        (g.star, Part::Star),
        (g.tabs, Part::Tabs),
        (g.sidebar, Part::Sidebar),
    ];
    parts.iter().find(|(r, _)| r.contains(x, y)).map(|&(_, p)| p)
}
