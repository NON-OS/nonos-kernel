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

mod binder;
mod cache;
mod consts;
mod extensions;
mod parse;
mod ticket;

pub use binder::compute_psk_binder;
pub use cache::SessionCache;
pub use consts::{MAX_ENTRIES, MAX_TICKET_LIFETIME_SECS};
pub use extensions::{build_psk_extension, build_psk_ke_modes_extension};
pub use parse::parse_new_session_ticket;
pub use ticket::SessionTicket;
