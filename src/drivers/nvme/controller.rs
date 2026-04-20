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

use crate::drivers::pci::PciDevice;
use crate::arch::x86_64::pci::mmio::{read_u32, write_u32, read_u64, write_u64};
use crate::mem::allocator::allocate_pages;

pub struct NvmeController {
    pci_device: PciDevice,
    bar0_base: u64,
    admin_queue: AdminQueue,
    io_queues: Vec<IoQueue>,
    namespace_count: u32,
}

struct AdminQueue {
    submission_queue: QueuePair,
    completion_queue: QueuePair,
    sq_tail: u16,
    cq_head: u16,
}

struct IoQueue {
    id: u16,
    submission_queue: QueuePair,
    completion_queue: QueuePair,
    sq_tail: u16,
    cq_head: u16,
}

struct QueuePair {
    base_addr: u64,
    size: u16,
    doorbell_offset: u32,
}

impl NvmeController {
    pub fn new(pci_device: PciDevice) -> Result<Self, &'static str> {
        let bar0 = pci_device.get_bar(0)?;
        let bar0_base = bar0 & !0xF;

        let mut controller = Self {
            pci_device,
            bar0_base,
            admin_queue: AdminQueue::new()?,
            io_queues: Vec::new(),
            namespace_count: 0,
        };

        controller.initialize()?;
        Ok(controller)
    }

    fn initialize(&mut self) -> Result<(), &'static str> {
        self.reset_controller()?;
        self.setup_admin_queues()?;
        self.enable_controller()?;
        self.identify_controller()?;
        self.setup_io_queues()?;
        Ok(())
    }

    fn reset_controller(&self) -> Result<(), &'static str> {
        let cc_addr = self.bar0_base + 0x14;
        write_u32(cc_addr, 0);

        let mut timeout = 1000;
        loop {
            let csts = read_u32(self.bar0_base + 0x1C);
            if csts & 1 == 0 {
                break;
            }
            if timeout == 0 {
                return Err("NVMe controller reset timeout");
            }
            timeout -= 1;
            crate::arch::x86_64::asm::sleep_ms(1);
        }
        Ok(())
    }

    fn setup_admin_queues(&mut self) -> Result<(), &'static str> {
        let asq_pages = allocate_pages(1)?;
        let acq_pages = allocate_pages(1)?;

        self.admin_queue.submission_queue.base_addr = asq_pages;
        self.admin_queue.completion_queue.base_addr = acq_pages;
        self.admin_queue.submission_queue.size = 64;
        self.admin_queue.completion_queue.size = 64;

        write_u64(self.bar0_base + 0x28, asq_pages);
        write_u64(self.bar0_base + 0x30, acq_pages);

        let aqa = ((63 << 16) | 63) as u32;
        write_u32(self.bar0_base + 0x24, aqa);

        Ok(())
    }

    fn enable_controller(&self) -> Result<(), &'static str> {
        let mut cc = 0u32;
        cc |= 1 << 0;
        cc |= 6 << 4;
        cc |= 4 << 7;
        cc |= 0 << 11;
        cc |= 1 << 14;
        cc |= 4 << 16;
        cc |= 6 << 20;

        write_u32(self.bar0_base + 0x14, cc);

        let mut timeout = 1000;
        loop {
            let csts = read_u32(self.bar0_base + 0x1C);
            if csts & 1 == 1 {
                break;
            }
            if timeout == 0 {
                return Err("NVMe controller enable timeout");
            }
            timeout -= 1;
            crate::arch::x86_64::asm::sleep_ms(1);
        }
        Ok(())
    }

    fn identify_controller(&mut self) -> Result<(), &'static str> {
        let data_pages = allocate_pages(1)?;
        let command = NvmeCommand::identify_controller(data_pages);

        self.submit_admin_command(command)?;
        self.wait_for_completion()?;

        let id_data = unsafe { core::slice::from_raw_parts(data_pages as *const u32, 1024) };
        self.namespace_count = id_data[516];

        Ok(())
    }

    fn setup_io_queues(&mut self) -> Result<(), &'static str> {
        let num_queues = 4;
        for i in 1..=num_queues {
            let sq_pages = allocate_pages(1)?;
            let cq_pages = allocate_pages(1)?;

            let create_cq_cmd = NvmeCommand::create_completion_queue(i, cq_pages, 256);
            self.submit_admin_command(create_cq_cmd)?;
            self.wait_for_completion()?;

            let create_sq_cmd = NvmeCommand::create_submission_queue(i, sq_pages, 256, i);
            self.submit_admin_command(create_sq_cmd)?;
            self.wait_for_completion()?;

            self.io_queues.push(IoQueue {
                id: i,
                submission_queue: QueuePair {
                    base_addr: sq_pages,
                    size: 256,
                    doorbell_offset: (2 * i * 4) as u32,
                },
                completion_queue: QueuePair {
                    base_addr: cq_pages,
                    size: 256,
                    doorbell_offset: ((2 * i + 1) * 4) as u32,
                },
                sq_tail: 0,
                cq_head: 0,
            });
        }
        Ok(())
    }

    fn submit_admin_command(&mut self, command: NvmeCommand) -> Result<(), &'static str> {
        let sq_base = self.admin_queue.submission_queue.base_addr;
        let slot = self.admin_queue.sq_tail as u64;
        let cmd_addr = sq_base + slot * 64;

        unsafe {
            core::ptr::write_volatile(cmd_addr as *mut NvmeCommand, command);
        }

        self.admin_queue.sq_tail = (self.admin_queue.sq_tail + 1) % 64;
        write_u32(self.bar0_base + 0x1000, self.admin_queue.sq_tail as u32);

        Ok(())
    }

    fn wait_for_completion(&mut self) -> Result<(), &'static str> {
        let cq_base = self.admin_queue.completion_queue.base_addr;
        let mut timeout = 10000;

        loop {
            let entry_addr = cq_base + (self.admin_queue.cq_head as u64) * 16;
            let status = unsafe { core::ptr::read_volatile((entry_addr + 14) as *const u16) };

            if status & 1 != self.admin_queue.cq_head & 1 {
                self.admin_queue.cq_head = (self.admin_queue.cq_head + 1) % 64;
                write_u32(self.bar0_base + 0x1004, self.admin_queue.cq_head as u32);
                break;
            }

            if timeout == 0 {
                return Err("NVMe command timeout");
            }
            timeout -= 1;
            crate::arch::x86_64::asm::pause();
        }
        Ok(())
    }

    pub fn read_blocks(&mut self, namespace: u32, lba: u64, blocks: u16, buffer: u64) -> Result<(), &'static str> {
        let queue_id = (lba % self.io_queues.len() as u64) as usize;
        let command = NvmeCommand::read(namespace, lba, blocks, buffer);

        self.submit_io_command(queue_id, command)?;
        self.wait_for_io_completion(queue_id)?;
        Ok(())
    }

    pub fn write_blocks(&mut self, namespace: u32, lba: u64, blocks: u16, buffer: u64) -> Result<(), &'static str> {
        let queue_id = (lba % self.io_queues.len() as u64) as usize;
        let command = NvmeCommand::write(namespace, lba, blocks, buffer);

        self.submit_io_command(queue_id, command)?;
        self.wait_for_io_completion(queue_id)?;
        Ok(())
    }

    fn submit_io_command(&mut self, queue_id: usize, command: NvmeCommand) -> Result<(), &'static str> {
        if queue_id >= self.io_queues.len() {
            return Err("Invalid queue ID");
        }

        let queue = &mut self.io_queues[queue_id];
        let sq_base = queue.submission_queue.base_addr;
        let slot = queue.sq_tail as u64;
        let cmd_addr = sq_base + slot * 64;

        unsafe {
            core::ptr::write_volatile(cmd_addr as *mut NvmeCommand, command);
        }

        queue.sq_tail = (queue.sq_tail + 1) % queue.submission_queue.size;
        let doorbell_addr = self.bar0_base + 0x1000 + queue.submission_queue.doorbell_offset as u64;
        write_u32(doorbell_addr, queue.sq_tail as u32);

        Ok(())
    }

    fn wait_for_io_completion(&mut self, queue_id: usize) -> Result<(), &'static str> {
        if queue_id >= self.io_queues.len() {
            return Err("Invalid queue ID");
        }

        let queue = &mut self.io_queues[queue_id];
        let cq_base = queue.completion_queue.base_addr;
        let mut timeout = 50000;

        loop {
            let entry_addr = cq_base + (queue.cq_head as u64) * 16;
            let status = unsafe { core::ptr::read_volatile((entry_addr + 14) as *const u16) };

            if status & 1 != queue.cq_head & 1 {
                queue.cq_head = (queue.cq_head + 1) % queue.completion_queue.size;
                let doorbell_addr = self.bar0_base + 0x1000 + queue.completion_queue.doorbell_offset as u64;
                write_u32(doorbell_addr, queue.cq_head as u32);
                break;
            }

            if timeout == 0 {
                return Err("NVMe I/O timeout");
            }
            timeout -= 1;
            crate::arch::x86_64::asm::pause();
        }
        Ok(())
    }
}

#[repr(C)]
struct NvmeCommand {
    cdw0: u32,
    nsid: u32,
    cdw2: u32,
    cdw3: u32,
    metadata: u64,
    prp1: u64,
    prp2: u64,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
}

impl NvmeCommand {
    fn identify_controller(buffer: u64) -> Self {
        Self {
            cdw0: 0x06,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            metadata: 0,
            prp1: buffer,
            prp2: 0,
            cdw10: 1,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }

    fn create_completion_queue(qid: u16, buffer: u64, size: u16) -> Self {
        Self {
            cdw0: 0x05,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            metadata: 0,
            prp1: buffer,
            prp2: 0,
            cdw10: ((size - 1) as u32) | ((qid as u32) << 16),
            cdw11: 1,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }

    fn create_submission_queue(qid: u16, buffer: u64, size: u16, cqid: u16) -> Self {
        Self {
            cdw0: 0x01,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            metadata: 0,
            prp1: buffer,
            prp2: 0,
            cdw10: ((size - 1) as u32) | ((qid as u32) << 16),
            cdw11: ((cqid as u32) << 16) | 1,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }

    fn read(nsid: u32, lba: u64, blocks: u16, buffer: u64) -> Self {
        Self {
            cdw0: 0x02,
            nsid,
            cdw2: 0,
            cdw3: 0,
            metadata: 0,
            prp1: buffer,
            prp2: 0,
            cdw10: lba as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: (blocks - 1) as u32,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }

    fn write(nsid: u32, lba: u64, blocks: u16, buffer: u64) -> Self {
        Self {
            cdw0: 0x01,
            nsid,
            cdw2: 0,
            cdw3: 0,
            metadata: 0,
            prp1: buffer,
            prp2: 0,
            cdw10: lba as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: (blocks - 1) as u32,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }
}

impl AdminQueue {
    fn new() -> Result<Self, &'static str> {
        Ok(Self {
            submission_queue: QueuePair {
                base_addr: 0,
                size: 0,
                doorbell_offset: 0,
            },
            completion_queue: QueuePair {
                base_addr: 0,
                size: 0,
                doorbell_offset: 0,
            },
            sq_tail: 0,
            cq_head: 0,
        })
    }
}