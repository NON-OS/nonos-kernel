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

extern crate alloc;

mod api;
pub mod engine;
pub mod history;
pub mod request;
pub mod session;
pub mod state;
pub mod tabs;

pub use api::{start, stop, is_running, navigate};
pub use engine::{render_page, BrowserEngine};
pub use history::{add_history, clear_history, get_history, HistoryEntry};
pub use request::{fetch_page, FetchOptions, FetchResult};
pub use session::{create_session, destroy_session, get_session, BrowserSession};
pub use state::{get_state, init, BrowserState};
pub use tabs::{active_tab, close_tab, create_tab, get_tabs, switch_tab, BrowserTab};
