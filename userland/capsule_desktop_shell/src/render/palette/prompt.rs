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

//! The colours of the shell's centred prompts: the app and package consents,
//! the live session's install offer and the Delete question.

use nonos_toolkit::theme::contrast::{at_least, BODY};
use nonos_toolkit::theme::Roles;

use super::glass::BEHIND;

/// A prompt's panel, its text and its two buttons, all opaque because the
/// prompts are painted with `fill_rect`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prompt {
    /// The panel.
    pub panel: u32,
    /// The outline round the panel and each button.
    pub border: u32,
    /// The title, the names and the button labels.
    pub fg: u32,
    /// The notes under the title.
    pub dim: u32,
    /// The button that goes ahead.
    pub approve: u32,
    /// The label on `approve`.
    pub approve_fg: u32,
    /// The button that leaves things as they are.
    pub cancel: u32,
    /// The label on `cancel`.
    pub cancel_fg: u32,
    /// A warning line, such as capabilities that did not fit.
    pub warn: u32,
}

impl Prompt {
    /// The prompt colours for a theme's roles.
    pub fn from_roles(r: &Roles) -> Self {
        Prompt {
            panel: r.surface.argb(),
            border: r.border_strong.argb(),
            fg: r.text.argb(),
            dim: r.text_2.argb(),
            approve: r.accent.argb(),
            approve_fg: r.on_accent.argb(),
            cancel: r.raised.argb(),
            cancel_fg: r.text.argb(),
            warn: r.warn.argb(),
        }
    }

    /// The label ink for a button of another fill: the first of the prompt's
    /// text, the panel's colour, black and white that reads on `fill`.
    pub fn ink_on(&self, fill: u32) -> u32 {
        [self.fg, self.panel]
            .into_iter()
            .chain(BEHIND)
            .find(|&ink| at_least(ink, fill, BODY))
            .unwrap_or(self.fg)
    }
}
