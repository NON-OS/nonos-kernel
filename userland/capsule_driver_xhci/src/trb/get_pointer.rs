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
    /// Read the 64-bit pointer carried in the first two dwords.
    /// On Command Completion / Transfer Event TRBs this is the
    /// address of the originating command/transfer TRB; on Link
    /// TRBs it is the wrap target.
    pub fn get_pointer(&self) -> u64 {
        (self.d0 as u64) | ((self.d1 as u64) << 32)
    }
}
