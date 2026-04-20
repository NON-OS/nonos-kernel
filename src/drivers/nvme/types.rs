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
use alloc::vec::Vec;
use crate::drivers::pci::PciDevice;

pub struct NvmeController {
    pub pci_device: PciDevice,
    pub bar0_base: u64,
    pub admin_queue: AdminQueue,
    pub io_queues: Vec<IoQueue>,
    pub namespace_count: u32,
}

pub struct AdminQueue {
    pub submission_queue: QueuePair,
    pub completion_queue: QueuePair,
    pub sq_tail: u16,
    pub cq_head: u16,
}

pub struct IoQueue {
    pub id: u16,
    pub submission_queue: QueuePair,
    pub completion_queue: QueuePair,
    pub sq_tail: u16,
    pub cq_head: u16,
}

pub struct QueuePair {
    pub base_addr: u64,
    pub size: u16,
    pub doorbell_offset: u32,
}

#[repr(C)]
pub struct NvmeCommand {
    pub cdw0: u32,
    pub nsid: u32,
    pub cdw2: u32,
    pub cdw3: u32,
    pub metadata: u64,
    pub prp1: u64,
    pub prp2: u64,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}