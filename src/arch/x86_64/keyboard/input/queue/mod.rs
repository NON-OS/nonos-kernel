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
pub mod state;
pub mod push;
pub mod pop;
pub mod api;

pub use config::{QueueConfig, DEFAULT_MAX_QUEUE_SIZE, MAX_ALLOWED_QUEUE_SIZE, DEFAULT_PRESSURE_THRESHOLD, MAX_COALESCE_COUNT};
pub use stats::QueueStats;
pub use wait::WaitHandle;
pub use push::push_event;
pub use pop::{pop_event, pop_event_filtered, peek_event, peek_event_filtered, drain_events, drain_events_filtered};
pub use api::{configure, get_config, queue_len, is_empty, clear, stats, total_events, dropped_events, shutdown, restart, is_shutdown, register_waiter, unregister_waiter, queue_pressure};

fn queue_pressure_inner() -> u8 {
    let queue = &state::INPUT_QUEUE;
    let inner = queue.inner.lock();
    let config = queue.config.read();
    let len = inner.events.len();
    if config.max_size == 0 {
        return 0;
    }
    ((len * 100) / config.max_size).min(100) as u8
}
