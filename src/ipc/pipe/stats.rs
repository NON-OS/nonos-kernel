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

use super::registry::PIPES;

pub fn pipe_count() -> usize {
    PIPES.lock().len()
}

pub fn get_pipe_stats() -> PipeStats {
    let pipes = PIPES.lock();
    let mut total_bytes = 0;
    let mut total_capacity = 0;
    for pipe in pipes.values() {
        total_bytes += pipe.bytes_available;
        total_capacity += pipe.capacity;
    }
    PipeStats { active_count: pipes.len(), total_bytes_buffered: total_bytes, total_capacity }
}

pub struct PipeStats {
    pub active_count: usize,
    pub total_bytes_buffered: usize,
    pub total_capacity: usize,
}
