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

use crate::browser::fetch::{constants, render_error, retryable_error};
use crate::browser::omnibox::{should_commit, Change};
use crate::browser::state::{State, View};

/// What a retry of a failed navigation must carry so it is the same
/// request: the form body of a POST, whether history was to be left alone
/// (Back, Forward, Reload), and whether the request had already left.
pub(super) struct Again {
    pub post: Option<String>,
    pub suppress: bool,
    pub requested: bool,
}

/* The document load failed. A transient network error retries the address
 * that was being loaded (not whatever is typed in the address bar), as the
 * same request: a POST stays a POST with its body, where the retry used to
 * go out as a GET without it. Any other error shows its page, under the
 * address that failed. A failure of a load that was stopped or overtaken
 * is dropped. */
/*
 * `code` is what the fetch stopped with, which the retry rule reads, and
 * `said` the sentence the reader is shown for it (`words`).
 */
pub(super) fn fail(state: &mut State, code: &str, said: &str, again: Again) {
    if !should_commit(state.ui.nav_gen, state.ui.loading_gen) {
        return;
    }
    let target = state.ui.last_target.clone();
    if retryable_error::retry_nav(code, again.post.is_some(), again.requested)
        && state.retries < constants::MAX_RETRIES
        && !target.is_empty()
    {
        state.retries += 1;
        state.status = alloc::format!(
            "Trying again ({} of {}): {}",
            state.retries,
            constants::MAX_RETRIES,
            said
        );
        state.pending_post = again.post;
        state.suppress_history_push = again.suppress;
        state.pending_nav = Some(target);
    } else {
        state.retries = 0;
        state.status = String::from(said);
        state.document = Some(render_error::render_error(said));
        state.box_doc = None;
        state.engine = None;
        state.page_dom = None;
        state.world = None;
        state.title.clear();
        state.view = View::Page;
        state.ui.current_url = target.clone();
        state.show_url(&target);
        state.mark(Change::Full);
    }
}
