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

pub(super) use super::find_state::is_replace_mode;
pub use super::find_state::{
    close_find, get_match_count, is_active, open_find, open_replace, toggle_case_sensitive,
};

pub use super::find_search::{find_next, find_prev};

pub use super::find_replace::{replace_all, replace_one};

pub use super::find_input::{set_find_pattern, set_replace_pattern};

pub(super) use super::find_input::{handle_find_key, handle_replace_key};
