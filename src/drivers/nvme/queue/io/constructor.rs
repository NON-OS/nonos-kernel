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

use super::super::super::error::NvmeError;
use super::super::pair::QueuePair;
use super::structure::IoQueue;

impl IoQueue {
    pub fn new(
        qid: u16,
        sq_depth: u16,
        cq_depth: u16,
        sq_doorbell: usize,
        cq_doorbell: usize,
    ) -> Result<Self, NvmeError> {
        if qid == 0 {
            return Err(NvmeError::InvalidQueueSize);
        }
        let pair = QueuePair::new(qid, sq_depth, cq_depth, sq_doorbell, cq_doorbell)?;
        Ok(Self { pair, associated_cq_id: qid })
    }
}
