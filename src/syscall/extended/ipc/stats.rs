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

use super::shm::SHM_SEGMENTS;
use super::sem::SEM_SETS;
use super::msg::MSG_QUEUES;

#[derive(Debug, Clone, Default)]
pub struct IpcStats {
    pub shm_segments: usize,
    pub shm_total_bytes: usize,
    pub shm_attachments: usize,
    pub sem_sets: usize,
    pub sem_total: usize,
    pub msg_queues: usize,
    pub msg_total: usize,
}

pub fn get_ipc_stats() -> IpcStats {
    let shm_segments = SHM_SEGMENTS.lock();
    let sem_sets = SEM_SETS.lock();
    let msg_queues = MSG_QUEUES.lock();

    IpcStats {
        shm_segments: shm_segments.len(),
        shm_total_bytes: shm_segments.values().map(|s| s.size).sum(),
        shm_attachments: shm_segments.values().map(|s| s.nattch as usize).sum(),
        sem_sets: sem_sets.len(),
        sem_total: sem_sets.values().map(|s| s.nsems).sum(),
        msg_queues: msg_queues.len(),
        msg_total: msg_queues.values().map(|q| q.qnum).sum(),
    }
}
