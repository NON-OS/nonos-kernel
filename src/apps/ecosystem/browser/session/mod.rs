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

mod cookie;
mod global;
mod parse;
mod storage;
mod tabs;
mod types;

pub use cookie::{Cookie, SameSite};
pub use global::{
    clear_expired_cookies, destroy_session, list_sessions, session_count, update_session,
};
pub use global::{create_session, get_active_session, get_session, set_active_session};
pub use parse::{format_cookie_header, parse_set_cookie};
pub use types::{BrowserSession, SessionStorage, SessionTab};
