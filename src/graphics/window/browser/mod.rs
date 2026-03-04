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

pub mod constants;
pub mod state;
pub mod html;
pub mod html_entities;
pub mod html_tags;
pub mod http;
pub mod http_nav;
pub mod http_poll;
pub mod input;
pub mod input_keys;
pub mod render;
pub mod find;
pub mod api;

pub use constants::*;
pub use api::{draw, handle_click, browser_key, browser_special_key, is_url_focused, poll_fetch};
pub use find::{
    open_find as browser_open_find,
    close_find as browser_close_find,
    is_active as browser_find_active,
    find_next as browser_find_next,
    find_prev as browser_find_prev,
    get_match_count as browser_get_match_count,
};
