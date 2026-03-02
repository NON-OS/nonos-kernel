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

use alloc::{string::String, sync::Arc, vec::Vec};
use x86_64::VirtAddr;

use crate::storage::{
    DeviceCapabilities, DeviceInfo, DeviceStatistics, IoFlags, IoOperation, IoRequest, IoResult,
    IoStatus, PowerState, SmartData, StorageDevice, StorageType,
};

use super::types::RaidMode;

pub struct RaidArray {
    members: Vec<Arc<dyn StorageDevice>>,
    mode: RaidMode,
    block_size: u32,
    info: DeviceInfo,
    stats: DeviceStatistics,
    stripe_blocks: u32,
}

impl RaidArray {
    pub fn new_linear(members: Vec<Arc<dyn StorageDevice>>) -> Result<Self, &'static str> {
        Self::new_impl(members, RaidMode::Linear, 0)
    }

    pub fn new_raid0(members: Vec<Arc<dyn StorageDevice>>, stripe_blocks: u32) -> Result<Self, &'static str> {
        if stripe_blocks == 0 {
            return Err("invalid stripe");
        }
        Self::new_impl(members, RaidMode::Raid0, stripe_blocks)
    }

    fn new_impl(members: Vec<Arc<dyn StorageDevice>>, mode: RaidMode, stripe_blocks: u32) -> Result<Self, &'static str> {
        if members.is_empty() {
            return Err("no members");
        }
        let bs = members.iter().map(|m| m.device_info().block_size).min().unwrap_or(4096);
        let capacity_bytes = match mode {
            RaidMode::Linear => members.iter().map(|m| m.device_info().capacity_bytes).sum(),
            RaidMode::Raid0 => {
                let min_cap = members.iter().map(|m| m.device_info().capacity_bytes).min().unwrap_or(0);
                (min_cap / bs as u64) * (members.len() as u64) * (bs as u64)
            }
        };
        let info = DeviceInfo {
            device_type: StorageType::VirtualDisk,
            vendor: String::from("NONOS"),
            model: match mode {
                RaidMode::Linear => String::from("RAID-LINEAR"),
                RaidMode::Raid0 => String::from("RAID-0"),
            },
            serial: String::from("RAID-0001"),
            firmware: String::from("raid-1.0"),
            firmware_version: String::from("raid-1.0"),
            capacity: capacity_bytes / bs as u64,
            capacity_bytes,
            block_size: bs,
            max_transfer_size: 1024 * 1024,
            max_queue_depth: 64,
            features: DeviceCapabilities::READ | DeviceCapabilities::WRITE | DeviceCapabilities::FLUSH,
        };
        Ok(Self {
            members,
            mode,
            block_size: bs,
            info,
            stats: DeviceStatistics::default(),
            stripe_blocks,
        })
    }

    #[inline]
    fn bs(&self) -> usize {
        self.block_size as usize
    }

    fn map_linear(&self, lba: u64) -> (usize, u64) {
        if self.members.is_empty() {
            return (0, 0);
        }
        let bs64 = self.block_size as u64;
        let mut remaining = lba * bs64;
        for (idx, m) in self.members.iter().enumerate() {
            let cap = m.device_info().capacity_bytes;
            if remaining < cap {
                return (idx, remaining / bs64);
            }
            remaining -= cap;
        }
        let last_idx = self.members.len().saturating_sub(1);
        let last_sectors = self.members.last().map(|m| m.total_sectors()).unwrap_or(0);
        (last_idx, last_sectors)
    }

    fn map_raid0(&self, lba: u64) -> (usize, u64) {
        let stripesz = self.stripe_blocks as u64;
        let n = self.members.len() as u64;
        let stripe = lba / stripesz;
        let disk = (stripe % n) as usize;
        let intra = lba % stripesz;
        let lba_on_disk = stripe / n * stripesz + intra;
        (disk, lba_on_disk)
    }

    fn submit_single(&self, member: &Arc<dyn StorageDevice>, mut req: IoRequest) -> Result<(), IoStatus> {
        member.submit_request(IoRequest { completion_callback: None, ..req.clone() })?;
        if let Some(cb) = req.completion_callback.take() {
            cb(IoResult {
                status: IoStatus::Success,
                bytes_transferred: (req.block_count as usize) * self.bs(),
                error_code: 0,
                completion_time: crate::time::timestamp_millis(),
            });
        }
        Ok(())
    }
}

impl StorageDevice for RaidArray {
    fn device_info(&self) -> DeviceInfo {
        self.info.clone()
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.info.features
    }

    fn submit_request(&self, request: IoRequest) -> Result<(), IoStatus> {
        let blocks = request.block_count as u64;
        if blocks == 0 {
            return Err(IoStatus::InvalidRequest);
        }
        let (disk0, lba0) = match self.mode {
            RaidMode::Linear => self.map_linear(request.lba),
            RaidMode::Raid0 => self.map_raid0(request.lba),
        };
        let (disk_end, _) = match self.mode {
            RaidMode::Linear => self.map_linear(request.lba + blocks - 1),
            RaidMode::Raid0 => self.map_raid0(request.lba + blocks - 1),
        };
        if disk0 != disk_end {
            return Err(IoStatus::InvalidRequest);
        }
        let member = &self.members[disk0];
        let mut req = request;
        req.lba = lba0;
        self.submit_single(member, req)
    }

    fn is_ready(&self) -> bool {
        self.members.iter().all(|m| m.is_ready())
    }

    fn statistics(&self) -> &DeviceStatistics {
        &self.stats
    }

    fn read_blocks(&self, start_block: u64, block_count: u32, buffer: &mut [u8]) -> Result<(), IoStatus> {
        let bs = self.bs();
        if buffer.len() < bs * block_count as usize {
            return Err(IoStatus::InvalidRequest);
        }
        let req = IoRequest {
            operation: IoOperation::Read,
            lba: start_block,
            block_count,
            buffer: VirtAddr::new(buffer.as_mut_ptr() as u64),
            buffer_size: bs * block_count as usize,
            priority: 0,
            flags: IoFlags::SYNC,
            status: IoStatus::Pending,
            completion_callback: None,
            request_id: 0,
            timestamp: crate::time::timestamp_millis(),
        };
        self.submit_request(req)
    }

    fn total_sectors(&self) -> u64 {
        self.info.capacity_bytes / self.info.block_size as u64
    }

    fn maintenance(&self) -> Result<(), &'static str> {
        Ok(())
    }

    fn smart_data(&self) -> Option<SmartData> {
        None
    }

    fn secure_erase(&self) -> Result<(), &'static str> {
        Err("erase not supported on RAID aggregator")
    }

    fn set_power_state(&self, _state: PowerState) -> Result<(), &'static str> {
        Ok(())
    }

    fn supports_secure_erase(&self) -> bool {
        false
    }

    fn verify_sanitize_completion(&self) -> Result<(), &'static str> {
        Ok(())
    }

    fn wait_for_completion(&self, _command_id: u16, _timeout_ms: u64) -> Result<(), &'static str> {
        Ok(())
    }

    fn parse_controller_identify(&self, _data: &[u8]) -> Result<(), &'static str> {
        Ok(())
    }
}
