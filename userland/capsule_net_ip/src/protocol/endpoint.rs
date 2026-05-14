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

//! Service + reply endpoint constants for `net.ip`. The numbers
//! match `Capsule.mk` so a renaming on either side surfaces
//! immediately when the kernel-side service registry refuses
//! the publish.

pub const SERVICE_PORT: u32 = 4410;
pub const REPLY_PORT: u32 = 4411;
pub const SERVICE_NAME: &str = "net.ip";
pub const REPLY_INBOX: &str = "endpoint.net.ip.reply";
