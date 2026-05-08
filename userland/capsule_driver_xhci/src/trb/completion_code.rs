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

use super::base::Trb;

impl Trb {
    /// Bits 31:24 of the third dword carry the completion code on
    /// Command Completion and Transfer Event TRBs. `CC_SUCCESS`
    /// is 1; everything else is an error or non-success status.
    pub fn completion_code(&self) -> u8 {
        ((self.d2 >> 24) & 0xFF) as u8
    }
}
