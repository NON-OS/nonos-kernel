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

pub const DIR: &[u8] = b"/home/.browser";
pub const STATE: &[u8] = b"/home/.browser/state.bin";

/// The largest record this build writes is well under this bound; anything
/// past it is not a record this build wrote, so the read is capped.
pub const MAX_FILE_BYTES: u32 = 128 * 1024;
