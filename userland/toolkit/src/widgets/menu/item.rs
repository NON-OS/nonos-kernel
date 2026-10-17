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

//! One entry of a menu and the builders that set it up.

/// One row of a menu: a label with an optional shortcut and tick, or a
/// separator. It holds only borrowed text and flags, so it copies freely,
/// and every builder is `const`, so a menu's items can be a constant.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Item<'a> {
    pub(super) label: &'a str,
    pub(super) shortcut: &'a str,
    pub(super) disabled: bool,
    pub(super) check: Option<bool>,
    pub(super) separator: bool,
}

impl<'a> Item<'a> {
    /// An item showing `label`, live, with no shortcut and no tick.
    pub const fn new(label: &'a str) -> Self {
        Item { label, shortcut: "", disabled: false, check: None, separator: false }
    }

    /// A hairline between two groups of items. It is never hit, and `next`
    /// steps over it.
    pub const fn separator() -> Self {
        Item { separator: true, ..Item::new("") }
    }

    /// The keys that do the same, such as `Ctrl+S`, drawn muted at the
    /// right of the row.
    pub const fn shortcut(mut self, keys: &'a str) -> Self {
        self.shortcut = keys;
        self
    }

    /// Draws the item in `disabled`. It is never hit, takes no hover or
    /// press, and `next` steps over it.
    pub const fn disabled(mut self) -> Self {
        self.disabled = true;
        self
    }

    /// An item that is on or off; on draws a tick at its left. Once any item
    /// has been given this, every row leaves room for the tick, so the
    /// labels line up.
    pub const fn checked(mut self, on: bool) -> Self {
        self.check = Some(on);
        self
    }

    /// Whether the item can be hit and chosen: neither a separator nor
    /// disabled.
    pub const fn live(&self) -> bool {
        !self.separator && !self.disabled
    }
}
