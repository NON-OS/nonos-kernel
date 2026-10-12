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

use crate::browser::omnibox::LineEdit;
use crate::browser::ui::settings_rows::Field;

/// The settings page's own state: its two text fields, the one with the
/// keyboard, what each last refused, and whether Remove all bookmarks
/// waits for its second click.
#[derive(Default)]
pub struct SettingsUi {
    pub focus: Option<Field>,
    pub proxy: LineEdit,
    pub search: LineEdit,
    pub proxy_err: Option<&'static str>,
    pub search_err: Option<&'static str>,
    pub armed: bool,
}

/// What a click on Remove all bookmarks does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Press {
    Arm,
    Clear,
    Nothing,
}

/// The first click on Remove all bookmarks arms it and the second, with
/// nothing between them, removes them; with none to remove it does nothing.
pub fn press(armed: bool, bookmarks: usize) -> Press {
    match (bookmarks, armed) {
        (0, _) => Press::Nothing,
        (_, false) => Press::Arm,
        (_, true) => Press::Clear,
    }
}

impl SettingsUi {
    pub fn field(&mut self, f: Field) -> &mut LineEdit {
        match f {
            Field::Proxy => &mut self.proxy,
            Field::Search => &mut self.search,
        }
    }

    /// Puts `text` back in field `f`, caret at its end, and drops what it
    /// last refused.
    pub fn refill(&mut self, f: Field, text: &str) {
        self.field(f).set(text);
        *self.refusal(f) = None;
    }

    /// What field `f` last refused, shown under it until it is typed in.
    pub fn refusal(&mut self, f: Field) -> &mut Option<&'static str> {
        match f {
            Field::Proxy => &mut self.proxy_err,
            Field::Search => &mut self.search_err,
        }
    }

    /// No field has the keyboard and nothing waits for a second click.
    pub fn settle(&mut self) {
        self.focus = None;
        self.armed = false;
    }
}

/// What the proxy field shows for a proxy at `host:port`.
pub fn proxy_text(host: &str, port: u16) -> String {
    alloc::format!("{}:{}", host, port)
}
