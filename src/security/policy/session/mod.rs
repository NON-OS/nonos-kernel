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


pub mod types;
pub mod helpers;
pub mod account;
pub mod session;
pub mod manager;
pub mod api;

pub use types::{PrivilegeLevel, SessionState, UID_ROOT, UID_ANONYMOUS, UID_DEFAULT, GID_ROOT, GID_WHEEL, GID_USERS};
pub use account::UserAccount;
pub use session::UserSession;
pub use manager::SessionManager;
pub use api::{session_manager, init, current_uid, current_username, current_cwd, getenv, setenv, chdir, environ, get_stats, SessionStats};
