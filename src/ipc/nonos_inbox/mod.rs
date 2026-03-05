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

//! Per-Module IPC Inbox System
//!
//! Provides bounded message queues for each module/process in the system.
//! Messages are delivered to inboxes where receivers can dequeue them.
//!
//! # Features
//!
//! - Per-module bounded queues with configurable capacity
//! - Timeout-based enqueue with spin-wait backoff
//! - Automatic inbox registration on first access
//! - Statistics tracking for monitoring
//!
//! # RAM-Only Design
//!
//! All inbox data is held in memory. No persistence layer exists.
//! On system reset, all inboxes and queued messages are lost.
//!
//! # Example
//!
//! ```ignore
//! use nonos_kernel::ipc::nonos_inbox;
//!
//! // Register an inbox for a module
//! nonos_inbox::register_inbox("my_module");
//!
//! // Enqueue a message with timeout
//! nonos_inbox::enqueue_with_timeout("my_module", msg, 1000)?;
//!
//! // Dequeue a message
//! if let Some(msg) = nonos_inbox::dequeue("my_module") {
//!     // Process message
//! }
//! ```

mod error;
mod inbox;
mod registry;
mod stats;

// Re-export public API
pub use error::InboxError;
pub use registry::{
    capacity, clear, dequeue, enqueue_with_timeout, exists, get_default_capacity,
    get_global_stats, get_inbox_stats, inbox_count, is_empty, is_full, len, list_inboxes,
    peek, register_inbox, register_inbox_with_capacity, set_default_capacity, try_dequeue,
    try_enqueue, unregister_inbox, DEFAULT_INBOX_CAPACITY, MAX_INBOX_CAPACITY,
    MIN_INBOX_CAPACITY,
};
pub use stats::InboxStatsSnapshot;
