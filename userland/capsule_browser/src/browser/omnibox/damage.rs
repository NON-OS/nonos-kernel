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

/* The parts of the window a change dirtied since the last paint. */
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Damage(pub u8);

impl Damage {
    pub const PILL: Damage = Damage(1);
    pub const TOOLBAR: Damage = Damage(2);
    pub const PAGE: Damage = Damage(8);
    /* The page moved under the viewport; its pixels can be shifted. */
    pub const SCROLL: Damage = Damage(16);
    pub const BUBBLE: Damage = Damage(32);
    pub const FULL: Damage = Damage(128);

    pub fn add(&mut self, d: Damage) {
        self.0 |= d.0;
    }

    pub fn has(self, d: Damage) -> bool {
        self.0 & d.0 != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}
