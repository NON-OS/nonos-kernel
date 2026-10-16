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

//! Colours typed by whether they may carry alpha, so a painter that writes pixels
//! without blending can only be given an opaque one.

/// A colour that covers what it is drawn over.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Opaque(u32);

impl Opaque {
    /// The colour with its alpha forced to full, whatever it arrived with.
    pub const fn new(argb: u32) -> Self {
        Self(argb | 0xFF00_0000)
    }

    /// The colour as a packed ARGB word.
    pub const fn argb(self) -> u32 {
        self.0
    }
}

/// A colour that may let what is behind it show through.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Translucent(u32);

impl Translucent {
    /// The colour with its alpha kept as given.
    pub const fn new(argb: u32) -> Self {
        Self(argb)
    }

    /// The colour as a packed ARGB word.
    pub const fn argb(self) -> u32 {
        self.0
    }
}
