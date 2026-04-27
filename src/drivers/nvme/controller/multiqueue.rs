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

use super::super::constants::{IO_QUEUE_DEPTH, MAX_IO_QUEUES};
use super::super::error::NvmeError;
use super::super::queue::IoQueue;
use super::structure::NvmeController;
use super::{admin, init};

impl NvmeController {
    pub(super) fn create_multiqueue_io_queues(&self) -> Result<(), NvmeError> {
        let cpu_count = crate::smp::cpu_count().max(1);
        let max_queues = self.capabilities.max_queue_entries.min(MAX_IO_QUEUES) as usize;
        let queue_count = cpu_count.min(max_queues);
        let admin = self.admin_queue.lock();
        let mut io_queues = self.io_queues.lock();
        let mut cpu_map = self.cpu_queue_map.lock();
        for qid in 1..=queue_count as u16 {
            let sq_db = init::calculate_sq_doorbell(self.mmio_base, self.doorbell_stride, qid);
            let cq_db = init::calculate_cq_doorbell(self.mmio_base, self.doorbell_stride, qid);
            let io_queue = IoQueue::new(qid, IO_QUEUE_DEPTH, IO_QUEUE_DEPTH, sq_db, cq_db)?;
            admin::create_io_completion_queue(
                &admin,
                qid,
                IO_QUEUE_DEPTH,
                io_queue.cq_phys(),
                0,
                false,
            )?;
            admin::create_io_submission_queue(
                &admin,
                qid,
                IO_QUEUE_DEPTH,
                io_queue.sq_phys(),
                qid,
                0,
            )?;
            io_queues.push(io_queue);
        }
        for cpu in 0..cpu_count {
            cpu_map.push(cpu % queue_count);
        }
        self.stats.set_io_queue_count(queue_count as u32);
        Ok(())
    }

    #[inline]
    pub fn get_queue_for_cpu(&self, cpu_id: usize) -> Option<usize> {
        let cpu_map = self.cpu_queue_map.lock();
        cpu_map.get(cpu_id).copied()
    }

    #[inline]
    pub fn current_cpu_queue_index(&self) -> usize {
        let cpu_id = crate::sched::current_cpu_id() as usize;
        self.get_queue_for_cpu(cpu_id).unwrap_or(0)
    }

    pub fn io_queue_count(&self) -> usize {
        self.io_queues.lock().len()
    }
}
