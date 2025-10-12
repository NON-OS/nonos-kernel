//! RAM-backed block device implementing StorageDevice for bring-up and production RAM-only usage. 
//! No-op on RAM disk; considered immediate success.

#![no_std]

extern crate alloc;

use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;
use x86_64::VirtAddr;

use crate::storage::{
    DeviceCapabilities, DeviceInfo, DeviceStatistics, IoFlags, IoOperation, IoRequest, IoResult,
    IoStatus, PowerState, SmartData, StorageDevice, StorageType, StorageManager,
};

pub struct RamDisk {
    data: RwLock<Vec<u8>>,
    block_size: u32,
    info: DeviceInfo,
    stats: DeviceStatistics,
}

impl RamDisk {
    pub fn new(capacity_bytes: u64, block_size: u32, vendor: &str, model: &str) -> Arc<Self> {
        let size = capacity_bytes as usize;
        let mut buf = Vec::with_capacity(size);
        // Safety: we immediately back the vector with zeroed capacity length for predictable mapping
        unsafe { buf.set_len(size) }
        let info = DeviceInfo {
            device_type: StorageType::RamDisk,
            vendor: String::from(vendor),
            model: String::from(model),
            serial: String::from("RAMDISK-0001"),
            firmware_version: String::from("rd-1.0"),
            capacity_bytes,
            block_size,
            max_transfer_size: 1024 * 1024,
            max_queue_depth: 64,
            features: DeviceCapabilities::READ | DeviceCapabilities::WRITE | DeviceCapabilities::FLUSH,
        };
        Arc::new(Self {
            data: RwLock::new(buf),
            block_size,
            info,
            stats: DeviceStatistics::default(),
        })
    }

    #[inline]
    fn bs(&self) -> usize {
        self.block_size as usize
    }

    fn read_into(&self, start_block: u64, block_count: u32, out: &mut [u8]) -> Result<(), IoStatus> {
        let start = (start_block as usize) * self.bs();
        let len = (block_count as usize) * self.bs();
        if out.len() < len {
            return Err(IoStatus::InvalidRequest);
        }
        let data = self.data.read();
        if start.checked_add(len).filter(|end| *end <= data.len()).is_none() {
            return Err(IoStatus::InvalidRequest);
        }
        out[..len].copy_from_slice(&data[start..start + len]);
        self.stats.reads_completed.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_read.fetch_add(len as u64, Ordering::Relaxed);
        Ok(())
    }

    fn write_from(&self, start_block: u64, block_count: u32, inp: &[u8]) -> Result<(), IoStatus> {
        let start = (start_block as usize) * self.bs();
        let len = (block_count as usize) * self.bs();
        if inp.len() < len {
            return Err(IoStatus::InvalidRequest);
        }
        let mut data = self.data.write();
        if start.checked_add(len).filter(|end| *end <= data.len()).is_none() {
            return Err(IoStatus::InvalidRequest);
        }
        data[start..start + len].copy_from_slice(&inp[..len]);
        self.stats.writes_completed.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_written.fetch_add(len as u64, Ordering::Relaxed);
        Ok(())
    }

    #[inline]
    unsafe fn buf_mut_from_virt<'a>(va: VirtAddr, len: usize) -> &'a mut [u8] {
        core::slice::from_raw_parts_mut(va.as_mut_ptr(), len)
    }

    #[inline]
    unsafe fn buf_from_virt<'a>(va: VirtAddr, len: usize) -> &'a [u8] {
        core::slice::from_raw_parts(va.as_ptr(), len)
    }

    /// Register a default RAM disk with the global manager if none exists.
    pub fn ensure_default_registered(manager: &StorageManager) {
        if manager.get_device(0).is_none() {
            // 64 MiB default RAM disk, 4KiB blocks
            let rd = RamDisk::new(64 * 1024 * 1024, 4096, "NONOS", "RAMDISK");
            let _ = manager.register_device(rd);
        }
    }
}

impl StorageDevice for RamDisk {
    fn device_info(&self) -> DeviceInfo {
        self.info.clone()
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.info.features
    }

    fn submit_request(&self, request: IoRequest) -> Result<(), IoStatus> {
        // Validate block-aligned size
        let byte_len = (request.block_count as usize) * self.bs();
        if request.buffer_size < byte_len {
            return Err(IoStatus::InvalidRequest);
        }

        let t0 = crate::time::timestamp_millis();
        match request.operation {
            IoOperation::Read => {
                unsafe {
                    let buf = Self::buf_mut_from_virt(request.buffer, request.buffer_size);
                    self.read_into(request.lba, request.block_count, buf)?;
                }
                let dt = crate::time::timestamp_millis().saturating_sub(t0);
                self.stats.average_read_latency.fetch_add(dt, Ordering::Relaxed);
                if let Some(cb) = request.completion_callback {
                    cb(IoResult {
                        status: IoStatus::Success,
                        bytes_transferred: byte_len,
                        error_code: 0,
                        completion_time: crate::time::timestamp_millis(),
                    });
                }
                Ok(())
            }
            IoOperation::Write => {
                unsafe {
                    let buf = Self::buf_from_virt(request.buffer, request.buffer_size);
                    self.write_from(request.lba, request.block_count, buf)?;
                }
                let dt = crate::time::timestamp_millis().saturating_sub(t0);
                self.stats
                    .average_write_latency
                    .fetch_add(dt, Ordering::Relaxed);
                if let Some(cb) = request.completion_callback {
                    cb(IoResult {
                        status: IoStatus::Success,
                        bytes_transferred: byte_len,
                        error_code: 0,
                        completion_time: crate::time::timestamp_millis(),
                    });
                }
                Ok(())
            }
            IoOperation::Trim | IoOperation::Flush | IoOperation::SecureErase => {
                // No-op on RAM disk; considered immediate success.
                if let Some(cb) = request.completion_callback {
                    cb(IoResult {
                        status: IoStatus::Success,
                        bytes_transferred: 0,
                        error_code: 0,
                        completion_time: crate::time::timestamp_millis(),
                    });
                }
                Ok(())
            }
        }
    }

    fn is_ready(&self) -> bool {
        true
    }

    fn statistics(&self) -> &DeviceStatistics {
        &self.stats
    }

    fn read_blocks(&self, start_block: u64, block_count: u32, buffer: &mut [u8]) -> Result<(), IoStatus> {
        self.read_into(start_block, block_count, buffer)
    }

    fn total_sectors(&self) -> u64 {
        (self.info.capacity_bytes / self.info.block_size as u64) as u64
    }

    fn maintenance(&self) -> Result<(), &'static str> {
        Ok(())
    }

    fn smart_data(&self) -> Option<SmartData> {
        Some(SmartData {
            temperature: 35,
            power_on_hours: 0,
            power_cycles: 0,
            unsafe_shutdowns: 0,
            media_errors: 0,
            error_log_entries: 0,
            critical_warning: 0,
            available_spare: 100,
            available_spare_threshold: 10,
            percentage_used: 0,
            data_units_read: self.stats.bytes_read.load(Ordering::Relaxed) / self.bs() as u64,
            data_units_written: self.stats.bytes_written.load(Ordering::Relaxed) / self.bs() as u64,
            host_read_commands: self.stats.reads_completed.load(Ordering::Relaxed),
            host_write_commands: self.stats.writes_completed.load(Ordering::Relaxed),
        })
    }

    fn secure_erase(&self) -> Result<(), &'static str> {
        let mut data = self.data.write();
        data.fill(0);
        self.stats.secure_erases_performed.fetch_add(1, Ordering::Relaxed);
        self.stats.last_secure_erase_time.store(crate::time::timestamp_millis(), Ordering::Relaxed);
        Ok(())
    }

    fn set_power_state(&self, _state: PowerState) -> Result<(), &'static str> {
        Ok(())
    }

    fn supports_secure_erase(&self) -> bool {
        true
    }

    fn verify_sanitize_completion(&self) -> Result<(), &'static str> {
        Ok(())
    }

    fn wait_for_completion(&self, _command_id: u16, _timeout_ms: u64) -> Result<(), &'static str> {
        // RAM disk doesn't queue hardware commands; completion is immediate.
        Ok(())
    }

    fn parse_controller_identify(&self, _data: &[u8]) -> Result<(), &'static str> {
        Ok(())
    }
}
