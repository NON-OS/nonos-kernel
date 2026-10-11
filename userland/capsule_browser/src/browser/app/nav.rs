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

use alloc::string::String;

use crate::browser::omnibox::Change;
use crate::browser::state::{Origin, State, View};

/* A pending navigation preempts any in-flight fetch. Page loads pull in
 * stylesheets and images that keep the socket busy well after the document
 * appears; without this the reader could never navigate away while those
 * sub-fetches ran. The load takes a new generation, stamped once `load`
 * returns; results that arrive later are committed only under it. */
pub(super) fn start_pending(state: &mut State) {
    let Some(target) = state.pending_nav.take() else {
        return;
    };
    if let Some(job) = state.fetch.take() {
        let _ = crate::browser::net::socket_close(state.sockets_port, job.handle);
    }
    if state.ui.origin != Origin::Auto {
        state.focus_page(None);
    }
    state.ui.origin = Origin::Auto;
    state.ui.nav_gen = state.ui.nav_gen.wrapping_add(1);
    state.ui.last_target = target.clone();
    /* Whatever loads next, the offer to switch to Anyone was for the page
     * that failed, and goes with it. */
    state.anyone_retry = None;
    state.ui.truncated = false;
    state.ui.hover_href = None;
    let result = crate::browser::fetch::load(state, &target);
    state.ui.loading_gen = state.ui.nav_gen;
    if let Err(code) = result {
        let host = crate::browser::url::parse(&target).map(|u| u.host).unwrap_or_default();
        let way = crate::browser::net::mixnet::way(&host);
        let said = crate::browser::fetch::words(code, way, &host);
        let msg = said.as_str();
        /* A load that failed before reading them must not hand a Back,
         * Forward or Reload flag, or a form body, to the next navigation. */
        state.suppress_history_push = false;
        state.pending_post = None;
        state.status = String::from(msg);
        state.document = Some(crate::browser::fetch::render_error(msg));
        state.box_doc = None;
        state.engine = None;
        state.page_dom = None;
        state.world = None;
        state.title.clear();
        state.view = View::Page;
        state.ui.current_url = target.clone();
        state.show_url(&target);
    }
    state.mark(Change::Full);
}
