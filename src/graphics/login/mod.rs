// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

mod auth;
mod input;
mod render;
mod state;

pub use auth::{
    attempt_login, create_new_wallet, get_current_user, get_current_wallet_address, import_wallet,
    logout,
};
pub use input::{handle_click, handle_key};
pub use render::draw;
pub use state::{get_screen_state, is_locked, is_login_required, lock_screen, ScreenState};
