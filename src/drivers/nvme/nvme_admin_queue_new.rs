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

use super::types::{AdminQueue, QueuePair};

pub fn nvme_admin_queue_new() -> Result<AdminQueue, &'static str> {
    Ok(AdminQueue {
        submission_queue: QueuePair { base_addr: 0, size: 0, doorbell_offset: 0 },
        completion_queue: QueuePair { base_addr: 0, size: 0, doorbell_offset: 0 },
        sq_tail: 0,
        cq_head: 0,
    })
}
