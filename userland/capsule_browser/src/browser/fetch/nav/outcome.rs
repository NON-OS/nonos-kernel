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

//! What a finished navigation's outcome amounts to on screen.

use alloc::string::String;

use crate::browser::state::{State, View};

/// Whether `raw` is a redirect that finish() will follow rather than show;
/// the page on screen stays until the response that will replace it.
pub(super) fn redirect(raw: &[u8]) -> bool {
    let Some(sep) = raw.windows(4).position(|w| w == b"\r\n\r\n") else { return false };
    let Ok(head) = core::str::from_utf8(&raw[..sep]) else { return false };
    let mut lines = head.lines();
    let status = lines.next().and_then(|l| l.split(' ').nth(1));
    let moved = matches!(status, Some("301" | "302" | "303" | "307" | "308"));
    moved
        && lines
            .any(|l| l.as_bytes().get(..9).is_some_and(|n| n.eq_ignore_ascii_case(b"location:")))
}

/// Show why the page could not be reached, in place of the page.
pub(super) fn unreached(state: &mut State, reason: &str) {
    state.retries = 0;
    state.status = String::from(reason);
    state.document = Some(crate::browser::fetch::render_error::render_error(reason));
    state.box_doc = None;
    state.engine = None;
    state.page_dom = None;
    state.world = None;
    state.title.clear();
    state.view = View::Page;
}
