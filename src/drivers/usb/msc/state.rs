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

use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;
use super::inquiry::InquiryResponse;
use super::capacity::StorageCapacity;
use super::sense::SenseData;
use super::cbw::CommandBlockWrapper;
use super::constants::{CBW_FLAG_DATA_IN, CBW_FLAG_DATA_OUT};

#[derive(Debug)]
pub struct MscDeviceState {
    pub slot_id: u8,
    pub lun: u8,
    pub bulk_in_ep: u8,
    pub bulk_out_ep: u8,
    pub max_lun: u8,
    pub inquiry: Option<InquiryResponse>,
    pub capacity: Option<StorageCapacity>,
    tag: AtomicU32,
    last_sense: Mutex<Option<SenseData>>,
}

impl MscDeviceState {
    pub fn new(slot_id: u8, bulk_in_ep: u8, bulk_out_ep: u8) -> Self {
        Self {
            slot_id,
            lun: 0,
            bulk_in_ep,
            bulk_out_ep,
            max_lun: 0,
            inquiry: None,
            capacity: None,
            tag: AtomicU32::new(1),
            last_sense: Mutex::new(None),
        }
    }

    pub fn next_tag(&self) -> u32 {
        self.tag.fetch_add(1, Ordering::Relaxed)
    }

    pub fn set_last_sense(&self, sense: SenseData) {
        *self.last_sense.lock() = Some(sense);
    }

    pub fn get_last_sense(&self) -> Option<SenseData> {
        self.last_sense.lock().clone()
    }

    pub fn clear_last_sense(&self) {
        *self.last_sense.lock() = None;
    }

    pub fn build_cbw(&self, cmd: &[u8], transfer_len: u32, direction_in: bool) -> CommandBlockWrapper {
        CommandBlockWrapper::new(
            self.next_tag(),
            transfer_len,
            if direction_in { CBW_FLAG_DATA_IN } else { CBW_FLAG_DATA_OUT },
            self.lun,
            cmd,
        )
    }
}
