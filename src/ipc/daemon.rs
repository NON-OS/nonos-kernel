// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//
//! IPC Daemon, background message processing for the IPC subsystem.

use core::sync::atomic::{AtomicBool, Ordering};

use super::nonos_channel::IPC_BUS;
use super::nonos_inbox;

/// Maximum messages processed per iteration
const MAX_MESSAGES_PER_ITERATION: usize = 128;

/// Default message timeout (ms)
const MESSAGE_TIMEOUT_MS: u64 = 5_000;

/// Daemon shutdown flag
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Request daemon shutdown
pub fn request_shutdown() {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

/// Check if shutdown was requested
#[inline]
pub fn is_shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

/// Reset shutdown flag
pub fn reset_shutdown() {
    SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
}

/// Process pending IPC messages (single iteration)
///
/// Dequeues messages from bus, validates, and routes to inboxes.
/// Returns number of messages processed.
pub fn process_message_queue() -> usize {
    let mut processed = 0;

    while processed < MAX_MESSAGES_PER_ITERATION {
        match IPC_BUS.get_next_message() {
            Some(message) => {
                // Validate integrity
                if !message.validate_integrity() {
                    processed += 1;
                    continue;
                }

                // Check destination is alive
                if !crate::modules::is_module_active(&message.to) {
                    IPC_BUS.remove_all_channels_for_module(&message.to);
                    processed += 1;
                    continue;
                }

                // Route to inbox
                nonos_inbox::register_inbox(&message.to);
                if !nonos_inbox::is_full(&message.to) {
                    let _ = nonos_inbox::enqueue_with_timeout(
                        &message.to,
                        message,
                        MESSAGE_TIMEOUT_MS,
                    );
                }
                processed += 1;
            }
            None => break,
        }
    }

    // Handle timeouts
    for msg in IPC_BUS.get_timed_out_messages() {
        IPC_BUS.remove_all_channels_for_module(&msg.to);
    }

    // Cleanup dead channels
    for idx in IPC_BUS.find_dead_channels() {
        IPC_BUS.remove_channel(idx);
    }

    processed
}

/// Run the IPC daemon loop
///
/// Blocks until `request_shutdown()` is called.
pub fn run_daemon() {
    while !is_shutdown_requested() {
        process_message_queue();
        crate::sched::yield_cpu();
    }
}
