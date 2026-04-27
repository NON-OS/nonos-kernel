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

pub mod api;
pub mod config;
pub mod pop;
pub mod push;
pub mod state;
pub mod stats;
pub mod wait;

pub use api::{
    clear, configure, dropped_events, get_config, is_empty, is_shutdown, queue_len, queue_pressure,
    register_waiter, restart, shutdown, stats, total_events, unregister_waiter,
};
pub use config::{
    QueueConfig, DEFAULT_MAX_QUEUE_SIZE, DEFAULT_PRESSURE_THRESHOLD, MAX_ALLOWED_QUEUE_SIZE,
    MAX_COALESCE_COUNT,
};
pub use pop::{
    drain_events, drain_events_filtered, peek_event, peek_event_filtered, pop_event,
    pop_event_filtered,
};
pub use push::push_event;
pub use stats::QueueStats;
pub use wait::WaitHandle;

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
