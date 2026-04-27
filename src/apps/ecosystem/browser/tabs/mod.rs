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

mod api;
mod tab_impl;
mod types;

pub use api::{
    active_tab, close_tab, create_tab, get_tab_count, get_tabs, go_back_tab, go_forward_tab,
    navigate_tab, next_tab, prev_tab, reload_tab, set_tab_error, set_tab_ready, stop_tab,
    switch_tab,
};
pub use types::{BrowserTab, SecurityStatus, TabStatus};
