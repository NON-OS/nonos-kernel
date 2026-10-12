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

//! A tab going out of view and coming back into it.

use alloc::boxed::Box;

use crate::browser::fetch::{cancel_all, NetWire};
use crate::browser::omnibox::Change;
use crate::browser::state::State;

/// The tab leaves the screen: its rasters go back to the budget the page
/// in view decodes under, and its kept connections are closed so their
/// streams at a proxy are free for that page. Its load keeps going.
pub fn blur(s: &mut State) {
    s.images.put_away(&s.image_queue);
    s.image_queue.clear();
    s.pool.close_idle(&mut NetWire(s.sockets_port));
}

/// The tab is on screen again: whole, with the images near its view
/// fetched again.
pub fn show(s: &mut State) {
    crate::browser::image::requeue_visible(s);
    s.mark(Change::Full);
}

/// A closed tab lets go of every connection it holds, and of its script
/// engine before its DOM: the engine holds a raw pointer into the DOM.
pub fn release(mut s: Box<State>) {
    cancel_all(&mut s);
    s.engine = None;
    s.world = None;
    s.page_dom = None;
}
