//! Minimal RAID aggregator.

#![no_std]

extern crate alloc;

use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::Ordering;
use x86_64::VirtAddr;

use crate::storage::{
    DeviceCapabilities, DeviceInfo, DeviceStatistics, IoFlags, IoOperation, IoRequest, IoResult,
    IoStatus, PowerState, SmartData, StorageDevice, StorageType,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaidMode {
    Linear,
    Raid0,
}

pub struct RaidArray {
    members: Vec<Arc<dyn StorageDevice>>,
    mode: RaidMode,
    block_size: u32,
    info: DeviceInfo,
    stats: DeviceStatistics,
    stripe_blocks: u32, // for RAID0, default 64 blocks per stripe
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
        // Use smallest block size across members to ensure alignment
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
            firmware_version: String::from("raid-1.0"),
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
        // Convert global LBA to (member index, member LBA)
        let bs64 = self.block_size as u64;
        let mut remaining = lba * bs64;
        for (idx, m) in self.members.iter().enumerate() {
            let cap = m.device_info().capacity_bytes;
            if remaining < cap {
                return (idx, remaining / bs64);
            }
            remaining -= cap;
        }
        // Past end -> map to last member end .
        (self.members.len() - 1, self.members.last().unwrap().total_sectors())
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
        member.submit_request(IoRequest { completion_callback: None, ..req })?;
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
        // Fast path: only support fully contained requests that map to a single member span.
        // Reject cross-boundary requests; higher layer can split.
        let blocks = request.block_count as u64;
        if blocks == 0 {
            return Err(IoStatus::InvalidRequest);
        }
        let (disk0, lba0) = match self.mode {
            RaidMode::Linear => self.map_linear(request.lba),
            RaidMode::Raid0 => self.map_raid0(request.lba),
        };
        // Compute last block mapping to ensure no boundary crossing
        let (diskN, _) = match self.mode {
            RaidMode::Linear => self.map_linear(request.lba + blocks - 1),
            RaidMode::Raid0 => self.map_raid0(request.lba + blocks - 1),
        };
        if disk0 != diskN {
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
            completion_callback: None,
            request_id: 0,
            timestamp: crate::time::timestamp_millis(),
        };
        self.submit_request(req)
    }

    fn total_sectors(&self) -> u64 {
        (self.info.capacity_bytes / self.info.block_size as u64) as u64
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
