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

pub mod config;
pub mod stats;
pub mod wait;
mod state;
mod push;
mod pop;
pub mod api;

pub use config::{QueueConfig, DEFAULT_MAX_QUEUE_SIZE, MAX_ALLOWED_QUEUE_SIZE, DEFAULT_PRESSURE_THRESHOLD, MAX_COALESCE_COUNT};
pub use stats::QueueStats;
pub use wait::WaitHandle;
pub use push::push_event;
pub use pop::{pop_event, pop_event_filtered, peek_event, peek_event_filtered, drain_events, drain_events_filtered};
pub use api::{configure, get_config, queue_len, is_empty, clear, stats, total_events, dropped_events, shutdown, restart, is_shutdown, register_waiter, unregister_waiter};

pub(super) use state::INPUT_QUEUE;
