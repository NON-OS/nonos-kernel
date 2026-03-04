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

pub mod render;
mod about;
mod process_manager;
pub mod wallet;
mod api;

pub use api::{
    draw_about,
    draw_process_manager,
    handle_process_manager_click,
    draw_browser,
    handle_browser_click,
    browser_key,
    browser_special_key,
    is_browser_url_focused,
    draw_wallet,
    handle_wallet_click,
    wallet_key,
    wallet_special_key,
    draw_ecosystem,
    handle_ecosystem_click,
    ecosystem_key,
    ecosystem_special_key,
    is_ecosystem_input_focused,
};
