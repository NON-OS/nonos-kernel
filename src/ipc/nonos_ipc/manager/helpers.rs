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
use super::super::channel::NonosIPCChannel;
use super::core::NonosIPCManager;
use super::types::{ManagerStatsSnapshot, MAX_QUEUE_CAPACITY};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

impl NonosIPCManager {
    pub fn set_default_queue_capacity(&self, capacity: usize) {
        self.default_queue_cap.store(capacity.min(MAX_QUEUE_CAPACITY) as u64, Ordering::Relaxed);
    }
    pub fn default_queue_capacity(&self) -> usize {
        self.default_queue_cap.load(Ordering::Relaxed) as usize
    }
    #[inline]
    pub fn channel_count(&self) -> usize {
        self.channels.read().len()
    }

    pub fn get_process_channels(&self, process_id: u64) -> Vec<u64> {
        self.process_channels.read().get(&process_id).cloned().unwrap_or_default()
    }

    pub fn get_channel(&self, channel_id: u64) -> Option<NonosIPCChannel> {
        self.channels.read().get(&channel_id).cloned()
    }

    pub fn get_stats(&self) -> ManagerStatsSnapshot {
        ManagerStatsSnapshot {
            messages_sent: self.stats.messages_sent.load(Ordering::Relaxed),
            messages_received: self.stats.messages_received.load(Ordering::Relaxed),
            messages_dropped: self.stats.messages_dropped.load(Ordering::Relaxed),
            channels_created: self.stats.channels_created.load(Ordering::Relaxed),
            channels_destroyed: self.stats.channels_destroyed.load(Ordering::Relaxed),
            active_channels: self.channel_count(),
        }
    }

    pub fn cleanup_process(&self, process_id: u64) {
        for channel_id in self.get_process_channels(process_id) {
            let _ = self.destroy_channel(process_id, channel_id);
        }
    }
}
