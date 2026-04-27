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
use super::types::{ManagerStats, DEFAULT_QUEUE_CAPACITY};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;
use spin::RwLock;

pub struct NonosIPCManager {
    pub(super) channels: RwLock<BTreeMap<u64, NonosIPCChannel>>,
    pub(super) process_channels: RwLock<BTreeMap<u64, Vec<u64>>>,
    pub(super) next_channel_id: AtomicU64,
    pub(super) next_message_id: AtomicU64,
    pub(super) default_queue_cap: AtomicU64,
    pub(super) stats: ManagerStats,
}

impl NonosIPCManager {
    pub const fn new() -> Self {
        Self {
            channels: RwLock::new(BTreeMap::new()),
            process_channels: RwLock::new(BTreeMap::new()),
            next_channel_id: AtomicU64::new(1),
            next_message_id: AtomicU64::new(1),
            default_queue_cap: AtomicU64::new(DEFAULT_QUEUE_CAPACITY as u64),
            stats: ManagerStats::new(),
        }
    }
}

impl Default for NonosIPCManager {
    fn default() -> Self {
        Self::new()
    }
}
