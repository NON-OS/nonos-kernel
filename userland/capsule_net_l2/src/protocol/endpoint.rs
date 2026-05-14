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

//! Reply inbox for `net.l2`. The kernel-side service registry
//! associates this name with the capsule's inbox handle; clients
//! send through `net.l2` and read responses from this reply
//! channel. Mirrors the pattern used by every other driver
//! capsule.

pub const REPLY_INBOX: &str = "endpoint.net.l2.reply";
