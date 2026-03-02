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

use super::types::{DeviceCapabilities, DeviceInfo, IoRequest, IoStatus, PowerState, SmartData};
use super::stats::DeviceStatistics;

pub trait StorageDevice: Send + Sync {
    fn device_info(&self) -> DeviceInfo;

    fn capabilities(&self) -> DeviceCapabilities;

    fn submit_request(&self, request: IoRequest) -> Result<(), IoStatus>;

    fn is_ready(&self) -> bool {
        true
    }

    fn statistics(&self) -> &DeviceStatistics;

    fn read_blocks(&self, start: u64, count: u32, buf: &mut [u8]) -> Result<(), IoStatus> {
        let _ = (start, count, buf);
        Err(IoStatus::InvalidRequest)
    }

    fn write_blocks(&self, start: u64, count: u32, buf: &[u8]) -> Result<(), IoStatus> {
        let _ = (start, count, buf);
        Err(IoStatus::InvalidRequest)
    }

    fn total_sectors(&self) -> u64 {
        0
    }

    fn sector_size(&self) -> u32 {
        512
    }

    fn maintenance(&self) -> Result<(), &'static str> {
        Ok(())
    }

    fn smart_data(&self) -> Option<SmartData> {
        None
    }

    fn secure_erase(&self) -> Result<(), &'static str> {
        Err("Secure erase not supported")
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
