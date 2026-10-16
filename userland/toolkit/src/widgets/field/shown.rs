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

//! Which part of a field's text is shown, and where the caret falls in it.

use alloc::string::String;

use super::Field;
use crate::widgets::text;

impl Field<'_> {
    /// Whether the field takes typing: focused and not disabled.
    pub(super) fn typing(&self) -> bool {
        self.state.focused && !self.state.disabled
    }

    /// The text shown in a box `w` wide, and the caret's byte index into it
    /// when one is drawn. Empty text shows the placeholder, truncated. Text
    /// that fits shows as is. Text too long shows its tail behind an ellipsis
    /// while typing, so the newest characters stay in view, and otherwise is
    /// truncated with an ellipsis. In the tail, the caret moves by where the
    /// kept end starts; a caret in the cut-off part sits just after the
    /// ellipsis.
    pub(super) fn shown(&self, w: u32, px: f32) -> (String, Option<usize>) {
        let caret = self.caret.filter(|_| self.typing());
        if self.text.is_empty() {
            return (text::truncate(self.placeholder, w, px), caret.map(|_| 0));
        }
        let caret = caret.map(|c| if self.text.is_char_boundary(c) { c } else { self.text.len() });
        if !self.typing() || text::width(self.text, px) <= w {
            return (text::truncate(self.text, w, px), caret);
        }
        let shown = text::tail(self.text, w, px);
        let lead = shown.chars().next().map_or(0, char::len_utf8);
        let from = self.text.len().saturating_sub(shown.len().saturating_sub(lead));
        (shown, caret.map(|c| lead.saturating_add(c.saturating_sub(from))))
    }
}
