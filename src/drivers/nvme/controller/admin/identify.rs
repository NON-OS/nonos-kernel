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

use alloc::vec::Vec;

use super::super::super::constants::*;
use super::super::super::dma::DmaRegion;
use super::super::super::error::NvmeError;
use super::super::super::namespace::{parse_namespace_list, Namespace};
use super::super::super::queue::AdminQueue;
use super::super::super::types::{ControllerIdentity, SubmissionEntry};

pub fn identify_controller(admin_queue: &AdminQueue) -> Result<ControllerIdentity, NvmeError> {
    let buffer = DmaRegion::allocate(IDENTIFY_DATA_SIZE)?;

    let cmd = SubmissionEntry::build_identify(0, 0, CNS_CONTROLLER, buffer.phys_u64());

    let _completion = admin_queue.submit_and_wait(cmd)?;

    // SAFETY: buffer is valid DMA region with 4096 bytes
    let data: &[u8; 4096] = unsafe { &*(buffer.as_ptr::<[u8; 4096]>()) };

    Ok(ControllerIdentity::from_data(data))
}

pub fn get_active_namespace_list(
    admin_queue: &AdminQueue,
    start_nsid: u32,
) -> Result<Vec<u32>, NvmeError> {
    let buffer = DmaRegion::allocate(NS_LIST_SIZE)?;

    let cmd = SubmissionEntry::build_identify(0, start_nsid, CNS_ACTIVE_NS_LIST, buffer.phys_u64());

    let _completion = admin_queue.submit_and_wait(cmd)?;

    // SAFETY: buffer is valid DMA region with 4096 bytes
    let data: &[u8; 4096] = unsafe { &*(buffer.as_ptr::<[u8; 4096]>()) };

    Ok(parse_namespace_list(data))
}

pub fn identify_namespace(admin_queue: &AdminQueue, nsid: u32) -> Result<Namespace, NvmeError> {
    if nsid == 0 {
        return Err(NvmeError::InvalidNamespaceId);
    }

    let buffer = DmaRegion::allocate(IDENTIFY_DATA_SIZE)?;

    let cmd = SubmissionEntry::build_identify(0, nsid, CNS_NAMESPACE, buffer.phys_u64());

    let _completion = admin_queue.submit_and_wait(cmd)?;

    // SAFETY: buffer is valid DMA region with 4096 bytes
    let data: &[u8; 4096] = unsafe { &*(buffer.as_ptr::<[u8; 4096]>()) };

    Namespace::from_identify_data(nsid, data)
}
