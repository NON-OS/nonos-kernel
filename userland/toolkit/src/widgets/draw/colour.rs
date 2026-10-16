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

//! The theme colours a blending painter accepts.

use crate::theme::{Opaque, Translucent};

/// A theme colour a blending painter accepts.
pub trait Paint: Copy {
    /// The packed ARGB value.
    fn argb(self) -> u32;
}

impl Paint for Opaque {
    fn argb(self) -> u32 {
        Opaque::argb(self)
    }
}

impl Paint for Translucent {
    fn argb(self) -> u32 {
        Translucent::argb(self)
    }
}
