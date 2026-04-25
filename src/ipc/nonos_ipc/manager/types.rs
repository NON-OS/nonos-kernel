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

use core::sync::atomic::AtomicU64;

pub(super) const DEFAULT_QUEUE_CAPACITY: usize = 1024;
pub(super) const MAX_QUEUE_CAPACITY: usize = 65536;
pub(super) const MAX_PAYLOAD_SIZE: usize = 1024 * 1024;
pub(super) const MAX_PARTICIPANTS: usize = 256;

pub(super) struct ManagerStats {
    pub messages_sent: AtomicU64,
    pub messages_received: AtomicU64,
    pub messages_dropped: AtomicU64,
    pub channels_created: AtomicU64,
    pub channels_destroyed: AtomicU64,
}

impl ManagerStats {
    pub(super) const fn new() -> Self {
        Self {
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            messages_dropped: AtomicU64::new(0),
            channels_created: AtomicU64::new(0),
            channels_destroyed: AtomicU64::new(0),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ManagerStatsSnapshot {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub messages_dropped: u64,
    pub channels_created: u64,
    pub channels_destroyed: u64,
    pub active_channels: usize,
}
