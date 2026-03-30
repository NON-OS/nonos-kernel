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

mod types;
mod tab_impl;
mod api;

pub use types::{TabStatus, SecurityStatus, BrowserTab};
pub use api::{create_tab, close_tab, switch_tab, active_tab, get_tabs, navigate_tab, go_back_tab, go_forward_tab, reload_tab, stop_tab, set_tab_ready, set_tab_error, get_tab_count, next_tab, prev_tab};
