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

use super::rect::Rect;

const BTN: i32 = 40;
const GAP: i32 = 6;
const PAD: i32 = 8;
const PILL_GAP: i32 = 12;
const ROUTE_W: i32 = 84;
const ROUTE_H: i32 = 26;
const ROUTE_PAD: i32 = 7;
const TEXT_X: i32 = 38;
const TEXT_GAP: i32 = 10;

/// Every hit target on the toolbar, and the box the address text is drawn
/// in. The painter, the click handler, the caret and the damage map all read
/// this, so a click always lands on what was drawn.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ToolbarGeom {
    pub back: Rect,
    pub fwd: Rect,
    pub reload: Rect,
    pub home: Rect,
    pub pill: Rect,
    pub route: Rect,
    pub text: Rect,
    pub menu: Rect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    Back,
    Fwd,
    Reload,
    Home,
    Pill,
    Route,
    Menu,
}

/// Back, forward, reload and home on the left, the menu on the right, and
/// the address pill filling what is left between them with the route badge
/// at its right end.
pub fn buttons(toolbar: Rect) -> ToolbarGeom {
    let y = toolbar.y + (toolbar.h - BTN).max(0) / 2;
    let at = |i: i32| Rect::new(toolbar.x + PAD + i * (BTN + GAP), y, BTN, BTN);
    let (back, fwd, reload, home) = (at(0), at(1), at(2), at(3));
    let menu = Rect::new(toolbar.right() - PAD - BTN, y, BTN, BTN);
    let px = home.right() + PILL_GAP;
    let pill = Rect::new(px, y, (menu.x - PILL_GAP - px).max(0), BTN);
    let rw = ROUTE_W.min((pill.w - 2 * ROUTE_PAD).max(0));
    let route = Rect::new(pill.right() - ROUTE_PAD - rw, y + (BTN - ROUTE_H) / 2, rw, ROUTE_H);
    let tx = pill.x + TEXT_X;
    let text = Rect::new(tx, y, (route.x - TEXT_GAP - tx).max(0), BTN);
    ToolbarGeom { back, fwd, reload, home, pill, route, text, menu }
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
        (g.menu, Part::Menu),
    ];
    parts.iter().find(|(r, _)| r.contains(x, y)).map(|&(_, p)| p)
}
