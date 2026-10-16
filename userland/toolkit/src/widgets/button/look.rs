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

//! The colours each kind of button draws with, before hover and press.

use super::{Button, Kind};
use crate::theme::contrast::{at_least, BODY};
use crate::theme::{roles, Opaque};

/// A button's body fill, outline and label ink. `None` draws nothing.
pub(super) struct Look {
    pub(super) fill: Option<Opaque>,
    pub(super) edge: Option<Opaque>,
    pub(super) ink: Opaque,
}

impl Button<'_> {
    /// The colours for the kind and state. Disabled keeps a `raised` body
    /// (none for `Plain`) and draws the label and any outline in
    /// `disabled`. An armed `Danger` fills with `danger` and labels in
    /// `bg` when that reads on it, else in `text`.
    pub(super) fn look(&self) -> Look {
        let r = roles();
        let look = |fill, edge, ink| Look { fill, edge, ink };
        if self.state.disabled {
            let fill = (self.kind != Kind::Plain).then_some(r.raised);
            return look(fill, fill.map(|_| r.disabled), r.disabled);
        }
        match self.kind {
            Kind::Primary => look(Some(r.accent), None, r.on_accent),
            Kind::Secondary => look(Some(r.raised), Some(r.border_strong), r.text),
            Kind::Plain => look(None, None, r.accent_text),
            Kind::Danger if self.state.selected => {
                let reads = at_least(r.bg.argb(), r.danger.argb(), BODY);
                look(Some(r.danger), None, if reads { r.bg } else { r.text })
            }
            Kind::Danger => look(Some(r.raised), Some(r.danger), r.danger),
        }
    }
}
