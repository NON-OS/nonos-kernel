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

use crate::browser::fetch::{redirect, render_error};
use crate::browser::http;
use crate::browser::http::response::ContentKind;
use crate::browser::omnibox::{should_commit, Change};
use crate::browser::shell::downloads::received;
use crate::browser::state::{State, View};

/* The document response arrived. A response for a load that was stopped or
 * overtaken by another navigation is dropped: the reader left that page,
 * and committing it would pull the view away from where they went. */
pub(super) fn finish(state: &mut State, raw: &[u8], suppress: bool) {
    if !should_commit(state.ui.nav_gen, state.ui.loading_gen) {
        return;
    }
    state.retries = 0;
    match http::response::parse(raw) {
        Some(resp) => {
            if matches!(resp.status, 301 | 302 | 303 | 307 | 308) {
                if let Some(loc) = resp.location {
                    return redirect::redirect(state, loc, suppress);
                }
            }
            state.redirect_count = 0;
            /* The page takes its history entry before its scripts run, so
             * an inline history.length or history.back() is counted from
             * this page and not the one before it. */
            let url = state.base.as_ref().map(crate::browser::url::to_string).unwrap_or_default();
            super::committed::committed(state, &url, suppress);
            super::commit_doc::commit_doc(state, &resp, raw.len());
            if resp.status / 100 == 2
                && !matches!(resp.content_kind, ContentKind::Html | ContentKind::Text)
            {
                state.downloaded = Some(received(url.clone(), resp.body));
            }
            state.visited = Some(url);
        }
        None => {
            state.redirect_count = 0;
            state.status = alloc::format!("bad resp raw={}", raw.len());
            state.document = Some(render_error::render_error(&super::incomplete::incomplete(raw)));
            state.box_doc = None;
            state.page_dom = None;
            state.world = None;
            state.engine = None;
            let target = state.ui.last_target.clone();
            state.ui.current_url = target.clone();
            state.show_url(&target);
            state.mark(Change::Full);
        }
    }
    state.view = View::Page;
}
