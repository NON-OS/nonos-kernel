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

mod about;
pub mod agents;
mod api;
pub mod developer;
pub mod marketplace;
mod process_manager;
pub mod render;
pub mod wallet;

pub use api::{
    agents_key, browser_key, browser_special_key, developer_key, draw_about, draw_agents,
    draw_browser, draw_developer, draw_ecosystem, draw_marketplace, draw_process_manager,
    draw_wallet, ecosystem_key, ecosystem_special_key, handle_agents_click, handle_browser_click,
    handle_developer_click, handle_ecosystem_click, handle_marketplace_click,
    handle_process_manager_click, handle_wallet_click, is_browser_url_focused,
    is_ecosystem_input_focused, marketplace_key, wallet_key, wallet_special_key,
};
