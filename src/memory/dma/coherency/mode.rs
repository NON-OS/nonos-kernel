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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coherency {
    Coherent,
    NonCoherent,
}

impl Coherency {
    pub const fn from_bool(coherent: bool) -> Self {
        if coherent {
            Self::Coherent
        } else {
            Self::NonCoherent
        }
    }

    pub const fn is_coherent(&self) -> bool {
        matches!(self, Self::Coherent)
    }

    pub const fn requires_cache_maintenance(&self) -> bool {
        matches!(self, Self::NonCoherent)
    }
}
