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

use core::sync::atomic::{AtomicU64, Ordering};

static TOTAL_QUEUES_CREATED: AtomicU64 = AtomicU64::new(0);
static TOTAL_MESSAGES_SENT: AtomicU64 = AtomicU64::new(0);
static TOTAL_MESSAGES_RECEIVED: AtomicU64 = AtomicU64::new(0);
static TOTAL_BYTES_SENT: AtomicU64 = AtomicU64::new(0);

pub fn record_queue_created() {
    TOTAL_QUEUES_CREATED.fetch_add(1, Ordering::Relaxed);
}

pub fn record_message_sent(bytes: usize) {
    TOTAL_MESSAGES_SENT.fetch_add(1, Ordering::Relaxed);
    TOTAL_BYTES_SENT.fetch_add(bytes as u64, Ordering::Relaxed);
}

pub fn record_message_received() {
    TOTAL_MESSAGES_RECEIVED.fetch_add(1, Ordering::Relaxed);
}

pub fn get_total_queues() -> u64 {
    TOTAL_QUEUES_CREATED.load(Ordering::Relaxed)
}

pub fn get_total_sent() -> u64 {
    TOTAL_MESSAGES_SENT.load(Ordering::Relaxed)
}

pub fn get_total_received() -> u64 {
    TOTAL_MESSAGES_RECEIVED.load(Ordering::Relaxed)
}

pub fn get_total_bytes() -> u64 {
    TOTAL_BYTES_SENT.load(Ordering::Relaxed)
}

pub struct MqStats {
    pub queues_created: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
}

pub fn get_stats() -> MqStats {
    MqStats {
        queues_created: TOTAL_QUEUES_CREATED.load(Ordering::Relaxed),
        messages_sent: TOTAL_MESSAGES_SENT.load(Ordering::Relaxed),
        messages_received: TOTAL_MESSAGES_RECEIVED.load(Ordering::Relaxed),
        bytes_sent: TOTAL_BYTES_SENT.load(Ordering::Relaxed),
    }
}

pub fn reset_stats() {
    TOTAL_QUEUES_CREATED.store(0, Ordering::Relaxed);
    TOTAL_MESSAGES_SENT.store(0, Ordering::Relaxed);
    TOTAL_MESSAGES_RECEIVED.store(0, Ordering::Relaxed);
    TOTAL_BYTES_SENT.store(0, Ordering::Relaxed);
}
