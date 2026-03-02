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

use core::sync::atomic::Ordering;

use crate::storage::{
    DeviceCapabilities, DeviceInfo, DeviceStatistics, IoOperation, IoRequest, IoResult,
    IoStatus, PowerState, SmartData, StorageDevice,
};
use super::ramdisk::RamDisk;

impl StorageDevice for RamDisk {
    fn device_info(&self) -> DeviceInfo {
        self.info.clone()
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.info.features
    }

    fn submit_request(&self, request: IoRequest) -> Result<(), IoStatus> {
        let byte_len = (request.block_count as usize) * self.bs();
        if request.buffer_size < byte_len {
            return Err(IoStatus::InvalidRequest);
        }

        let t0 = crate::time::timestamp_millis();
        match request.operation {
            IoOperation::Read => {
                // SAFETY: Buffer address validated by caller
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
                // SAFETY: Buffer address validated by caller
                unsafe {
                    let buf = Self::buf_from_virt(request.buffer, request.buffer_size);
                    self.write_from(request.lba, request.block_count, buf)?;
                }
                let dt = crate::time::timestamp_millis().saturating_sub(t0);
                self.stats.average_write_latency.fetch_add(dt, Ordering::Relaxed);
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
        self.info.capacity_bytes / self.info.block_size as u64
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
            reallocated_sectors: 0,
            pending_sectors: 0,
            health_status: 0,
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
        Ok(())
    }

    fn parse_controller_identify(&self, _data: &[u8]) -> Result<(), &'static str> {
        Ok(())
    }
}
