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

pub mod engine;
pub mod form;
pub mod history;
pub mod js;
pub mod navigate;
pub mod request;
pub mod session;
pub mod state;
pub mod tabs;

pub use engine::{render_page, render_to_lines, BrowserEngine};
pub use form::{
    build_form_urlencoded, collect_form_data, prepare_form_submission, resolve_url, url_encode,
    FormAction,
};
pub use history::{add_history, clear_history, get_history, HistoryEntry};
pub use js::{JsRuntime, JsValue};
pub use navigate::{
    cancel_navigation, is_navigating, is_running, navigate, navigate_with_post, poll_navigation,
    start, stop,
};
pub use request::{fetch_page, FetchError, FetchOptions, FetchResult};
pub use session::{create_session, destroy_session, get_session, BrowserSession};
pub use state::{get_state, init, BrowserState};
pub use tabs::{active_tab, close_tab, create_tab, get_tabs, switch_tab, BrowserTab};
