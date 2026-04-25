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

mod helpers;
mod maintenance;
mod records;
mod resolve;
mod v4_v6;

pub use maintenance::{check_dns_timeouts, clear_cache, get_recent_queries, get_stats, init};
pub use records::{resolve_any, resolve_cname, resolve_mx, resolve_ns, resolve_txt};
pub use resolve::resolve;
pub use v4_v6::{resolve_v4, resolve_v6};
