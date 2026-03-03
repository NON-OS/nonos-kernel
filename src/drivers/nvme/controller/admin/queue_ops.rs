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

use super::super::super::constants::*;
use super::super::super::error::NvmeError;
use super::super::super::queue::AdminQueue;
use super::super::super::types::SubmissionEntry;

pub fn create_io_completion_queue(
    admin_queue: &AdminQueue,
    qid: u16,
    qsize: u16,
    queue_phys: u64,
    irq_vector: u16,
    irq_enabled: bool,
) -> Result<(), NvmeError> {
    if qid == 0 {
        return Err(NvmeError::InvalidQueueSize);
    }

    let cmd =
        SubmissionEntry::build_create_cq(0, qid, qsize, queue_phys, irq_vector, irq_enabled);

    let _completion = admin_queue.submit_and_wait(cmd)?;
    Ok(())
}

pub fn create_io_submission_queue(
    admin_queue: &AdminQueue,
    qid: u16,
    qsize: u16,
    queue_phys: u64,
    cqid: u16,
    priority: u8,
) -> Result<(), NvmeError> {
    if qid == 0 {
        return Err(NvmeError::InvalidQueueSize);
    }

    let cmd = SubmissionEntry::build_create_sq(0, qid, qsize, queue_phys, cqid, priority);

    let _completion = admin_queue.submit_and_wait(cmd)?;
    Ok(())
}

pub fn delete_io_submission_queue(admin_queue: &AdminQueue, qid: u16) -> Result<(), NvmeError> {
    if qid == 0 {
        return Err(NvmeError::InvalidQueueSize);
    }

    let mut cmd = SubmissionEntry::new();
    cmd.set_opcode(ADMIN_OPC_DELETE_SQ);
    cmd.cdw10 = qid as u32;

    let _completion = admin_queue.submit_and_wait(cmd)?;
    Ok(())
}

pub fn delete_io_completion_queue(admin_queue: &AdminQueue, qid: u16) -> Result<(), NvmeError> {
    if qid == 0 {
        return Err(NvmeError::InvalidQueueSize);
    }

    let mut cmd = SubmissionEntry::new();
    cmd.set_opcode(ADMIN_OPC_DELETE_CQ);
    cmd.cdw10 = qid as u32;

    let _completion = admin_queue.submit_and_wait(cmd)?;
    Ok(())
}
