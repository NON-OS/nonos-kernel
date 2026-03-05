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

use alloc::collections::VecDeque;
use alloc::vec::Vec;

const _RX_BUFFER_SIZE: usize = 64;

const _FRAME_TYPE_MGMT: u8 = 0;
const _FRAME_TYPE_CTRL: u8 = 1;
const _FRAME_TYPE_DATA: u8 = 2;

const _MGMT_SUBTYPE_BEACON: u8 = 8;
const _MGMT_SUBTYPE_PROBE_RESP: u8 = 5;
const _MGMT_SUBTYPE_AUTH: u8 = 11;
const _MGMT_SUBTYPE_DEAUTH: u8 = 12;
const _MGMT_SUBTYPE_ASSOC_RESP: u8 = 1;
const _MGMT_SUBTYPE_DISASSOC: u8 = 10;

const _DATA_SUBTYPE_DATA: u8 = 0;
const _DATA_SUBTYPE_QOS_DATA: u8 = 8;

#[derive(Debug, Clone)]
pub struct _RxFrameInfo {
    pub frame_type: _FrameType,
    pub subtype: u8,
    pub to_ds: bool,
    pub from_ds: bool,
    pub protected: bool,
    pub addr1: [u8; 6],
    pub addr2: [u8; 6],
    pub addr3: [u8; 6],
    pub seq_num: u16,
    pub payload_offset: usize,
    pub payload_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum _FrameType {
    Management,
    Control,
    Data,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct _RxFrame {
    pub info: _RxFrameInfo,
    pub data: Vec<u8>,
    pub rssi: i8,
    pub channel: u8,
    pub timestamp: u64,
}

pub struct _RxProcessor {
    bssid_filter: Option<[u8; 6]>,
    our_mac: [u8; 6],
    pub promiscuous: bool,
    data_queue: VecDeque<_RxFrame>,
    mgmt_queue: VecDeque<_RxFrame>,
    frames_received: u64,
    frames_filtered: u64,
    frames_malformed: u64,
}

impl _RxProcessor {
    pub fn new() -> Self {
        Self {
            bssid_filter: None,
            our_mac: [0; 6],
            promiscuous: false,
            data_queue: VecDeque::with_capacity(_RX_BUFFER_SIZE),
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

    pub fn process_frame(&mut self, raw_frame: &[u8], rssi: i8, channel: u8) -> Option<_RxFrameInfo> {
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
                if self.data_queue.len() >= _RX_BUFFER_SIZE {
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

    fn parse_frame(&self, data: &[u8]) -> Option<_RxFrameInfo> {
        if data.len() < 24 {
            return None;
        }

        let frame_control = u16::from_le_bytes([data[0], data[1]]);

        let frame_type_bits = ((frame_control >> 2) & 0x03) as u8;
        let subtype = ((frame_control >> 4) & 0x0F) as u8;
        let to_ds = (frame_control & 0x0100) != 0;
        let from_ds = (frame_control & 0x0200) != 0;
        let protected = (frame_control & 0x4000) != 0;

        let frame_type = match frame_type_bits {
            _FRAME_TYPE_MGMT => _FrameType::Management,
            _FRAME_TYPE_CTRL => _FrameType::Control,
            _FRAME_TYPE_DATA => _FrameType::Data,
            _ => _FrameType::Unknown,
        };

        let mut addr1 = [0u8; 6];
        let mut addr2 = [0u8; 6];
        let mut addr3 = [0u8; 6];
        addr1.copy_from_slice(&data[4..10]);
        addr2.copy_from_slice(&data[10..16]);
        addr3.copy_from_slice(&data[16..22]);

        let seq_ctrl = u16::from_le_bytes([data[22], data[23]]);
        let seq_num = seq_ctrl >> 4;

        let mut payload_offset = 24;

        if frame_type == _FrameType::Data && (subtype & 0x08) != 0 {
            payload_offset += 2;
        }

        if (frame_control & 0x8000) != 0 {
            payload_offset += 4;
        }

        if to_ds && from_ds {
            payload_offset += 6;
        }

        let payload_len = if data.len() > payload_offset {
            data.len() - payload_offset
        } else {
            0
        };

        Some(_RxFrameInfo {
            frame_type,
            subtype,
            to_ds,
            from_ds,
            protected,
            addr1,
            addr2,
            addr3,
            seq_num,
            payload_offset,
            payload_len,
        })
    }

    fn should_accept(&self, info: &_RxFrameInfo) -> bool {
        if info.addr1[0] & 0x01 != 0 {
            if let Some(bssid) = self.bssid_filter {
                return info.addr3 == bssid || info.addr2 == bssid;
            }
            return true;
        }

        if info.addr1 == self.our_mac {
            if let Some(bssid) = self.bssid_filter {
                return info.addr2 == bssid || info.addr3 == bssid;
            }
            return true;
        }

        if info.frame_type == _FrameType::Management {
            match info.subtype {
                _MGMT_SUBTYPE_BEACON | _MGMT_SUBTYPE_PROBE_RESP => {
                    return true;
                }
                _ => {}
            }
        }

        false
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

    pub fn stats(&self) -> (u64, u64, u64) {
        (self.frames_received, self.frames_filtered, self.frames_malformed)
    }

    pub fn clear(&mut self) {
        self.data_queue.clear();
        self.mgmt_queue.clear();
    }

    pub fn get_source_mac(info: &_RxFrameInfo) -> [u8; 6] {
        match (info.to_ds, info.from_ds) {
            (false, false) => info.addr2,
            (true, false) => info.addr2,
            (false, true) => info.addr3,
            (true, true) => info.addr2,
        }
    }

    pub fn get_dest_mac(info: &_RxFrameInfo) -> [u8; 6] {
        match (info.to_ds, info.from_ds) {
            (false, false) => info.addr1,
            (true, false) => info.addr3,
            (false, true) => info.addr1,
            (true, true) => info.addr3,
        }
    }

    pub fn get_bssid(info: &_RxFrameInfo) -> [u8; 6] {
        match (info.to_ds, info.from_ds) {
            (false, false) => info.addr3,
            (true, false) => info.addr1,
            (false, true) => info.addr2,
            (true, true) => [0; 6],
        }
    }

    pub fn is_eapol_frame(data: &[u8], info: &_RxFrameInfo) -> bool {
        if info.payload_len < 8 {
            return false;
        }

        let payload = &data[info.payload_offset..];

        if payload.len() >= 8
            && payload[0] == 0xAA
            && payload[1] == 0xAA
            && payload[2] == 0x03
        {
            let ether_type = u16::from_be_bytes([payload[6], payload[7]]);
            return ether_type == 0x888E;
        }

        false
    }
}
