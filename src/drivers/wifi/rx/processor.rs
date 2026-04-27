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
use super::types::_RxFrame;
use alloc::collections::VecDeque;

pub struct _RxProcessor {
    pub(super) bssid_filter: Option<[u8; 6]>,
    pub(super) our_mac: [u8; 6],
    pub promiscuous: bool,
    pub(super) data_queue: VecDeque<_RxFrame>,
    pub(super) mgmt_queue: VecDeque<_RxFrame>,
    pub(super) frames_received: u64,
    pub(super) frames_filtered: u64,
    pub(super) frames_malformed: u64,
}

impl _RxProcessor {
    pub fn new() -> Self {
        Self {
            bssid_filter: None,
            our_mac: [0; 6],
            promiscuous: false,
            data_queue: VecDeque::with_capacity(RX_BUFFER_SIZE),
            mgmt_queue: VecDeque::with_capacity(16),
            frames_received: 0,
            frames_filtered: 0,
            frames_malformed: 0,
        }
    }

    pub fn set_bssid_filter(&mut self, bssid: Option<[u8; 6]>) {
        self.bssid_filter = bssid;
    }

    pub fn set_our_mac(&mut self, mac: [u8; 6]) {
        self.our_mac = mac;
    }

    pub fn set_promiscuous(&mut self, enable: bool) {
        self.promiscuous = enable;
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        (self.frames_received, self.frames_filtered, self.frames_malformed)
    }

    pub fn clear(&mut self) {
        self.data_queue.clear();
        self.mgmt_queue.clear();
    }
}
