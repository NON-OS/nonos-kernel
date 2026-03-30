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
pub enum DmaDirection {
    ToDevice,
    FromDevice,
    Bidirectional,
}

impl DmaDirection {
    pub const fn writes_to_device(&self) -> bool {
        matches!(self, Self::ToDevice | Self::Bidirectional)
    }

    pub const fn reads_from_device(&self) -> bool {
        matches!(self, Self::FromDevice | Self::Bidirectional)
    }
}

impl Default for DmaDirection {
    fn default() -> Self {
        Self::Bidirectional
    }
}
