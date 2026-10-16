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

use nonos_app_skeleton::paint::PaintBuffer;
use nonos_toolkit::theme::roles;

use crate::app::state::VideoApp;
use crate::ui::frame::{region, sidebar, topbar};
use crate::ui::layout::Rect;
use crate::ui::screen::Route;

pub fn hint(route: Route) -> &'static str {
    match route {
        Route::Files => "Type to search this folder",
        _ => "Type to search videos",
    }
}

pub fn has_tools(route: Route) -> bool {
    matches!(route, Route::Library | Route::Files)
}

/// Where a page draws its videos, for the click test: the same rect the
/// page's painter fills, or `None` on a page with no video list.
pub fn content(route: Route, body: Rect) -> Option<Rect> {
    match route {
        Route::Library => Some(super::library::area(body)),
        Route::Files => Some(super::files::area(body)),
        _ => None,
    }
}

pub fn paint_route(fb: &mut PaintBuffer, app: &VideoApp) {
    let ground = roles().bg.argb();
    for px in fb.pixels.iter_mut() {
        *px = ground;
    }
    let (w, h) = (fb.width, fb.height);
    let route = app.route();
    sidebar::paint_sidebar(fb, route, app.browse.items.len());
    /* Search and the view switch act on the video list, so they show only
     * on the pages that have one. */
    if has_tools(route) {
        topbar::paint_search(fb, w, h, hint(route), &app.browse.query);
        topbar::paint_tools(fb, w, h, app.browse.grid);
    }
    let body = region::body(w, h);
    match route {
        Route::Library => super::library::paint(fb, app, body),
        Route::Files => super::files::paint(fb, app, body),
        Route::Details => super::details::paint(fb, app, body),
        Route::Player => {}
    }
}
