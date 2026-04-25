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

use super::constants::RX_BUFFER_SIZE;
use super::processor::_RxProcessor;
use super::types::{_FrameType, _RxFrame, _RxFrameInfo};

impl _RxProcessor {
    pub fn process_frame(
        &mut self,
        raw_frame: &[u8],
        rssi: i8,
        channel: u8,
    ) -> Option<_RxFrameInfo> {
        self.frames_received += 1;
        let info = match self.parse_frame(raw_frame) {
            Some(info) => info,
            None => {
                self.frames_malformed += 1;
                return None;
            }
        };
        if !self.promiscuous && !self.should_accept(&info) {
            self.frames_filtered += 1;
            return None;
        }
        let frame = _RxFrame {
            info: info.clone(),
            data: raw_frame.to_vec(),
            rssi,
            channel,
            timestamp: crate::arch::x86_64::time::tsc::elapsed_us(),
        };
        match info.frame_type {
            _FrameType::Data => {
                if self.data_queue.len() >= RX_BUFFER_SIZE {
                    self.data_queue.pop_front();
                }
                self.data_queue.push_back(frame);
            }
            _FrameType::Management => {
                if self.mgmt_queue.len() >= 16 {
                    self.mgmt_queue.pop_front();
                }
                self.mgmt_queue.push_back(frame);
            }
            _ => {}
        }
        Some(info)
    }

    pub fn dequeue_data(&mut self) -> Option<_RxFrame> {
        self.data_queue.pop_front()
    }
    pub fn dequeue_mgmt(&mut self) -> Option<_RxFrame> {
        self.mgmt_queue.pop_front()
    }
    pub fn has_data(&self) -> bool {
        !self.data_queue.is_empty()
    }
    pub fn has_mgmt(&self) -> bool {
        !self.mgmt_queue.is_empty()
    }
    pub fn data_queue_len(&self) -> usize {
        self.data_queue.len()
    }
}
