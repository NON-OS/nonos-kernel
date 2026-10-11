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

use crate::browser::http::response::Response;
use crate::browser::reader::title::title_of;
use crate::browser::state::State;

use super::render_response::{render_response, Rendered};
use super::style_hold::StyleHold;

/* Put a parsed response on screen: an HTML DOM is homed and its scripts
 * run, text renders as lines. */
pub(super) fn commit_doc(state: &mut State, resp: &Response, raw_len: usize) {
    let (rendered, count) = render_response(resp);
    state.scroll = 0;
    state.ui.select = None;
    state.status =
        alloc::format!("{} raw={} body={} fl={}", resp.status, raw_len, resp.body.len(), count);
    /* A fresh document drops any stylesheets gathered for the last one. */
    state.css_queue.clear();
    state.style_hold = StyleHold::default();
    state.script_queue.clear();
    state.page_css.clear();
    state.ui.truncated = false;
    state.title.clear();
    match rendered {
        Rendered::Html(dom) => {
            /* Drop the prior page's engine before its DOM disappears, then
             * home the new DOM and run its scripts against that stable
             * address. */
            state.engine = None;
            state.ui.truncated = super::committed::parser_cut(&dom);
            state.page_dom = Some(dom);
            state.document = None;
            super::commit_html::commit_html(state);
            state.title = state.page_dom.as_ref().and_then(title_of).unwrap_or_default();
            super::enqueue_css::enqueue_css(state);
            /* Stylesheets are render-blocking: if the page pulls in external
             * CSS, hold the first paint until it arrives so the reader never
             * sees the unstyled document flash. */
            if !state.css_queue.is_empty() {
                state.box_doc = None;
                state.status = alloc::string::String::from("loading styles");
                state.style_hold = StyleHold::from(nonos_libc::mk_uptime_ms());
            }
        }
        Rendered::Lines(d) => {
            state.document = Some(d);
            state.box_doc = None;
            state.page_dom = None;
            state.world = None;
            state.engine = None;
        }
        Rendered::Nothing => {
            state.document = None;
            state.box_doc = None;
            state.page_dom = None;
            state.world = None;
            state.engine = None;
        }
    }
    crate::browser::image::enqueue_from_doc(state);
}
