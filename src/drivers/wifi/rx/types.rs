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

use super::constants::*;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum _FrameType {
    Management,
    Control,
    Data,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgmtSubtype {
    AssocResp,
    Beacon,
    ProbeResp,
    Auth,
    Deauth,
    Disassoc,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSubtype {
    Data,
    QosData,
    Unknown,
}

impl MgmtSubtype {
    pub fn from_u8(subtype: u8) -> Self {
        match subtype {
            MGMT_SUBTYPE_ASSOC_RESP => MgmtSubtype::AssocResp,
            MGMT_SUBTYPE_BEACON => MgmtSubtype::Beacon,
            MGMT_SUBTYPE_PROBE_RESP => MgmtSubtype::ProbeResp,
            MGMT_SUBTYPE_AUTH => MgmtSubtype::Auth,
            MGMT_SUBTYPE_DEAUTH => MgmtSubtype::Deauth,
            MGMT_SUBTYPE_DISASSOC => MgmtSubtype::Disassoc,
            _ => MgmtSubtype::Unknown,
        }
    }
}

impl DataSubtype {
    pub fn from_u8(subtype: u8) -> Self {
        match subtype {
            DATA_SUBTYPE_DATA => DataSubtype::Data,
            DATA_SUBTYPE_QOS_DATA => DataSubtype::QosData,
            _ => DataSubtype::Unknown,
        }
    }
}

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

impl _RxFrameInfo {
    pub fn mgmt_subtype(&self) -> MgmtSubtype {
        MgmtSubtype::from_u8(self.subtype)
    }
    pub fn data_subtype(&self) -> DataSubtype {
        DataSubtype::from_u8(self.subtype)
    }
    pub fn is_auth_frame(&self) -> bool {
        self.frame_type == _FrameType::Management && self.subtype == MGMT_SUBTYPE_AUTH
    }
    pub fn is_deauth_frame(&self) -> bool {
        self.frame_type == _FrameType::Management && self.subtype == MGMT_SUBTYPE_DEAUTH
    }
    pub fn is_assoc_resp(&self) -> bool {
        self.frame_type == _FrameType::Management && self.subtype == MGMT_SUBTYPE_ASSOC_RESP
    }
    pub fn is_disassoc_frame(&self) -> bool {
        self.frame_type == _FrameType::Management && self.subtype == MGMT_SUBTYPE_DISASSOC
    }
    pub fn is_qos_data(&self) -> bool {
        self.frame_type == _FrameType::Data && self.subtype == DATA_SUBTYPE_QOS_DATA
    }
}

#[derive(Debug, Clone)]
pub struct _RxFrame {
    pub info: _RxFrameInfo,
    pub data: Vec<u8>,
    pub rssi: i8,
    pub channel: u8,
    pub timestamp: u64,
}
