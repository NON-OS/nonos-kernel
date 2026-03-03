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

pub fn get_feature(admin_queue: &AdminQueue, fid: u8, nsid: u32) -> Result<u32, NvmeError> {
    let cmd = SubmissionEntry::build_get_features(0, fid, nsid);
    let completion = admin_queue.submit_and_wait(cmd)?;
    Ok(completion.dw0)
}

pub fn set_feature(
    admin_queue: &AdminQueue,
    fid: u8,
    nsid: u32,
    value: u32,
) -> Result<(), NvmeError> {
    let cmd = SubmissionEntry::build_set_features(0, fid, nsid, value);
    let _completion = admin_queue.submit_and_wait(cmd)?;
    Ok(())
}

pub fn get_number_of_queues(admin_queue: &AdminQueue) -> Result<(u16, u16), NvmeError> {
    let result = get_feature(admin_queue, FID_NUM_QUEUES, 0)?;
    let nsqa = (result & 0xFFFF) as u16;
    let ncqa = ((result >> 16) & 0xFFFF) as u16;
    Ok((nsqa + 1, ncqa + 1))
}

pub fn set_number_of_queues(
    admin_queue: &AdminQueue,
    num_sq: u16,
    num_cq: u16,
) -> Result<(u16, u16), NvmeError> {
    let nsqr = num_sq.saturating_sub(1) as u32;
    let ncqr = num_cq.saturating_sub(1) as u32;
    let value = nsqr | (ncqr << 16);

    let cmd = SubmissionEntry::build_set_features(0, FID_NUM_QUEUES, 0, value);
    let completion = admin_queue.submit_and_wait(cmd)?;

    let nsqa = (completion.dw0 & 0xFFFF) as u16;
    let ncqa = ((completion.dw0 >> 16) & 0xFFFF) as u16;
    Ok((nsqa + 1, ncqa + 1))
}

pub fn abort_command(admin_queue: &AdminQueue, sqid: u16, cid: u16) -> Result<bool, NvmeError> {
    let cmd = SubmissionEntry::build_abort(0, sqid, cid);
    let completion = admin_queue.submit_and_wait(cmd)?;

    let aborted = (completion.dw0 & 0x1) == 0;
    Ok(aborted)
}
