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

//! The field, the builders that set it up and the size it prefers.

use crate::design::scale::scale;
use crate::design::size::{CONTROL_H, FIELD_W};
use crate::icons::IconId;
use crate::widgets::State;

/// A one-line text field showing `text`, or `placeholder` while it is empty,
/// with an optional icon before it.
#[derive(Clone, Copy, Debug)]
pub struct Field<'a> {
    pub(super) text: &'a str,
    pub(super) placeholder: &'a str,
    pub(super) icon: Option<IconId>,
    pub(super) caret: Option<usize>,
    pub(super) state: State,
}

impl<'a> Field<'a> {
    /// A field holding `text`, with no placeholder, icon or caret.
    pub fn new(text: &'a str) -> Self {
        Field { text, placeholder: "", icon: None, caret: None, state: State::default() }
    }

    /// The icon drawn before the text, in `muted`.
    pub fn icon(mut self, id: IconId) -> Self {
        self.icon = Some(id);
        self
    }

    /// The hint shown in `quiet` while the text is empty.
    pub fn placeholder(mut self, placeholder: &'a str) -> Self {
        self.placeholder = placeholder;
        self
    }

    /// The caret, as a byte index into the text; `None` draws none. An index
    /// past the end or inside a character is taken as the end. The caret is
    /// drawn only while the field is focused and not disabled.
    pub fn caret(mut self, caret: Option<usize>) -> Self {
        self.caret = caret;
        self
    }

    /// The state the app reports. `pressed` and `selected` are ignored.
    pub fn state(mut self, s: State) -> Self {
        self.state = s;
        self
    }

    /// `FIELD_W` by `CONTROL_H`, with or without an icon.
    pub fn size(&self) -> (u32, u32) {
        let s = scale();
        (s.px(FIELD_W), s.px(CONTROL_H))
    }
}
