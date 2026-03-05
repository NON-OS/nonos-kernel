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


pub mod events;
pub mod manager;
pub mod state;

pub use events::{AppEvent, poll_event, peek_event, event_count, clear_events};
pub use manager::{resume_app, start_app, stop_app, suspend_app, get_app_type, is_network_app, restart_app, fail_app};
pub use state::LifecycleState;
