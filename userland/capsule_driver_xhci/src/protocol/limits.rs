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

// Reply payload sizes. Status word is the leading i32. Layouts
// are mirrored verbatim by the kernel-side decoder.

pub const STATUS_LEN: usize = 4;
pub const CONTROLLER_STATUS_PAYLOAD_LEN: usize = 52;
pub const PORT_ENTRY_BYTES: usize = 8;
pub const MAX_PORTS_REPORTED: usize = 255;
pub const PORT_STATUS_HEADER_BYTES: usize = 4;
