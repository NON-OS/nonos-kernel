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

use nonos_app_skeleton::PaintBuffer;

use crate::browser::omnibox::Damage;
use crate::browser::state::State;
use crate::browser::ui::layout::compute;

pub(super) fn paint_app(state: &mut State, fb: &mut PaintBuffer) {
    /* The window can be resized after the page laid out; when the surface
     * width or page height changes, reflow the document to the new size so
     * it fills the window and vh units and fixed boxes track its height. */
    state.layout = compute(fb.width as i32, fb.height as i32, state.sidebar);
    let size = (state.layout.content.w as u32, state.layout.content.h as u32);
    if size.0 != 0 && size != (state.viewport_w, state.viewport_h) {
        (state.viewport_w, state.viewport_h) = size;
        /* The page's scripts hear it before the reflow, so what their
         * media queries and resize handlers change is laid out with it. */
        if let Some(dom) = state.page_dom.as_mut() {
            dom.viewport = size;
        }
        if let Some(engine) = state.engine.as_ref() {
            engine.viewport_changed();
            crate::browser::event::take_script_nav(state);
        }
        crate::browser::event::relayout(state);
        state.track.painting = Damage::FULL;
    }
    let parts = core::mem::replace(&mut state.track.painting, Damage::FULL);
    /* A whole-window paint covers every change recorded so far. */
    if parts.has(Damage::FULL) {
        state.track.damage = Damage::default();
        state.track.painted_gen = state.track.paint_gen;
    }
    crate::browser::paint::paint(state, fb, parts);
}
