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

//! The heights a dialog's lines of text take, and the lines its body wraps
//! to.

use alloc::string::String;
use alloc::vec::Vec;

use super::Dialog;
use crate::design::scale::scale;
use crate::design::size::{LINE_GAP, SPACE};
use crate::font::ttf::line_height;
use crate::widgets::text;

impl Dialog<'_> {
    /// The height of a line of body text.
    pub(super) fn lh() -> u32 {
        line_height(Self::px()).max(0) as u32
    }

    /// The height of the title's line.
    pub(super) fn title_h() -> u32 {
        line_height(Self::title_px()).max(0) as u32
    }

    /// The room `n` body lines take under the title: `SPACE.sm`, then the
    /// lines `LINE_GAP` apart; none for no line.
    pub(super) fn block(n: u32) -> u32 {
        let lines = n * Self::lh() + n.saturating_sub(1) * scale().px(LINE_GAP);
        lines + Self::sm() * n.min(1)
    }

    /// `SPACE.sm`, the gap under the title and over the note.
    pub(super) fn sm() -> u32 {
        scale().px(u32::from(SPACE.sm))
    }

    /// The lines the body wraps to in `w`, at most `most`, each cut with `…`
    /// to fit. The last takes the rest of the body, so it is cut when more
    /// would follow.
    pub(super) fn lines(&self, w: u32, most: usize) -> Vec<String> {
        let (t, px) = (self.body, Self::px());
        let spans = text::wrap(t, w, px).into_iter().take(most).enumerate();
        let end = |i: usize, e: usize| if i + 1 == most { t.len() } else { e };
        spans.map(|(i, (s, e))| text::truncate(t[s..end(i, e)].trim_end(), w, px)).collect()
    }
}
