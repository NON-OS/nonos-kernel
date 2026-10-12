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

use nonos_app_skeleton::{EventOutcome, InputEvent};

use crate::browser::omnibox::{scroll_to, Change, ScrollAct};
use crate::browser::state::{State, View};

/* Move the page by `act` within what it can scroll, measured against the
 * real viewport height. Returns whether the offset changed; a key or wheel
 * notch at the end of the page changes nothing and draws nothing. */
pub(super) fn apply_scroll(state: &mut State, act: ScrollAct) -> bool {
    let content_h = match (state.box_doc.as_ref(), state.document.as_ref()) {
        (Some(b), _) => b.content_h,
        (None, Some(d)) => d.content_h,
        (None, None) => 0,
    };
    let next = scroll_to(state.scroll, content_h, state.viewport_h, act);
    if next == state.scroll {
        return false;
    }
    moved_to(state, next);
    /* What a scroll listener asked for (another scroll, a navigation) is
     * acted on now. */
    if state.engine.is_some() {
        super::script_nav::take_script_nav(state);
    }
    true
}

/* The page is now at `next`: draw it there, and tell its scripts. */
fn moved_to(state: &mut State, next: u32) {
    state.scroll = next;
    /* Images evicted for the byte budget come back as they scroll into view. */
    crate::browser::image::requeue_visible(state);
    state.mark(Change::Scroll);
    /* The page's scripts read where it is and hear that it moved: a sticky
     * header or a list that loads more as it nears its end listens for
     * this. What a listener changes is laid out by the timer gate. */
    if let Some(dom) = state.page_dom.as_mut() {
        dom.scroll_y = next;
    }
    if let Some(engine) = state.engine.as_ref() {
        if engine.dispatch_event(-1, "scroll") > 0 {
            state.track.js_dirty = true;
        }
    }
}

/* How many times a scroll listener that scrolls again is followed in one
 * go; a pair of listeners can ask each other forever. */
const FOLLOW_HOPS: u32 = 4;

/* A page's own scrollTo, scrollBy or scrollIntoView moved the document's
 * scroll_y while it ran (dom::script_scroll). The window follows once the
 * run is over, held to the page as laid out now, and the page hears
 * scroll as it does for the reader's own. Before any layout there is
 * nothing to hold it to, and the wish waits for one. */
pub(super) fn follow_script_scroll(state: &mut State) {
    for _ in 0..FOLLOW_HOPS {
        let Some(want) = state.page_dom.as_ref().map(|d| d.scroll_y) else { return };
        let Some(content_h) = state.box_doc.as_ref().map(|b| b.content_h) else { return };
        if want == state.scroll {
            return;
        }
        let act = ScrollAct::To(want as i64);
        let next = scroll_to(state.scroll, content_h, state.viewport_h, act);
        if next == state.scroll {
            /* Held back to where it already is: the document agrees. */
            if let Some(dom) = state.page_dom.as_mut() {
                dom.scroll_y = next;
            }
            return;
        }
        moved_to(state, next);
    }
}

/* The wheel scrolls the page, and only while a page is shown with nothing
 * over it. */
pub(super) fn on_wheel(state: &mut State, event: InputEvent) -> EventOutcome {
    if state.view != View::Page {
        return EventOutcome::Idle;
    }
    /* The wheel over an open select list closes it rather than leave it
     * behind as the page moves. */
    super::select_open::close_select(state);
    match apply_scroll(state, ScrollAct::Wheel(event.delta_y)) {
        true => EventOutcome::Repaint,
        false => EventOutcome::Idle,
    }
}
