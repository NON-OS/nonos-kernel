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
pub mod stats;
pub mod tracker_blocker;
pub mod url_cleaner;

pub use api::{init, start, stop, is_running};
pub use stats::{
    get_stats, reset_stats, PrivacyStats,
    increment_params_stripped, increment_fingerprint_blocked, increment_cookies_blocked,
};
pub use tracker_blocker::{is_tracker, should_block, should_block as should_block_request, BLOCKED_DOMAINS, blocked_domain_count};
pub use url_cleaner::{clean_url, strip_tracking_params, tracking_param_count};
