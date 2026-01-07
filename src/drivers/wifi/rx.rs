// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::error::WifiError;
use super::tx::{IEEE80211_FTYPE_DATA, IEEE80211_FTYPE_MGMT};
use alloc::string::ToString;
use alloc::vec::Vec;

pub const RX_RES_STATUS_DECRYPT_OK: u32 = 1 << 3;
pub const RX_RES_STATUS_MIC_OK: u32 = 1 << 5;
pub const RX_RES_STATUS_CRCF32_OK: u32 = 1 << 6;
pub const RX_RES_STATUS_OVERRUN: u32 = 1 << 24;

#[repr(C, packed)]
pub struct RxPhyInfo {
    pub non_cfg_phy_cnt: u8,
    pub cfg_phy_cnt: u8,
    pub stat_id: u8,
    pub reserved: u8,
    pub timestamp: u32,
    pub beacon_time_stamp: u32,
    pub phy_flags: u16,
    pub channel: u16,
    pub non_cfg_phy: [u32; 8],
    pub rate_n_flags: u32,
    pub byte_count: u16,
    pub frame_time: u16,
}

#[repr(C, packed)]
pub struct RxMpduRes {
    pub byte_count: u16,
    pub reserved: u16,
    pub status: u32,
}

#[derive(Debug, Clone)]
pub struct RxFrame {
    pub frame_type: FrameType,
    pub src_addr: [u8; 6],
    pub dst_addr: [u8; 6],
    pub bssid: [u8; 6],
    pub rssi: i8,
    pub channel: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Beacon,
    ProbeResponse,
    AssocResponse,
    ReassocResponse,
    Auth,
    Deauth,
    Disassoc,
    Data,
    QosData,
    Action,
    Unknown,
}

pub struct RxProcessor {
    bssid_filter: Option<[u8; 6]>,
    pub promiscuous: bool,
}

impl RxProcessor {
    pub fn new() -> Self {
        Self {
            bssid_filter: None,
            promiscuous: false,
        }
    }

    pub fn set_bssid_filter(&mut self, bssid: Option<[u8; 6]>) {
        self.bssid_filter = bssid;
    }

    pub fn set_promiscuous(&mut self, enable: bool) {
        self.promiscuous = enable;
    }

    pub fn process_mpdu(
        &self,
        data: &[u8],
        phy_info: &RxPhyInfo,
    ) -> Result<Option<RxFrame>, WifiError> {
        if data.len() < 24 {
            return Ok(None);
        }

        let fc = u16::from_le_bytes([data[0], data[1]]);
        let frame_type = fc & super::constants::FRAME_TYPE_MASK;
        let frame_subtype = fc & super::constants::FRAME_SUBTYPE_MASK;

        let mut src_addr = [0u8; 6];
        let mut dst_addr = [0u8; 6];
        let mut bssid = [0u8; 6];

        dst_addr.copy_from_slice(&data[4..10]);
        src_addr.copy_from_slice(&data[10..16]);
        bssid.copy_from_slice(&data[16..22]);

        if let Some(filter_bssid) = self.bssid_filter {
            if !self.promiscuous && bssid != filter_bssid {
                return Ok(None);
            }
        }

        let ftype = match (frame_type, frame_subtype) {
            (IEEE80211_FTYPE_MGMT, 0x80) => FrameType::Beacon,
            (IEEE80211_FTYPE_MGMT, 0x50) => FrameType::ProbeResponse,
            (IEEE80211_FTYPE_MGMT, 0x10) => FrameType::AssocResponse,
            (IEEE80211_FTYPE_MGMT, 0x30) => FrameType::ReassocResponse,
            (IEEE80211_FTYPE_MGMT, 0xB0) => FrameType::Auth,
            (IEEE80211_FTYPE_MGMT, 0xC0) => FrameType::Deauth,
            (IEEE80211_FTYPE_MGMT, 0xA0) => FrameType::Disassoc,
            (IEEE80211_FTYPE_MGMT, 0xD0) => FrameType::Action,
            (IEEE80211_FTYPE_DATA, 0x00) => FrameType::Data,
            (IEEE80211_FTYPE_DATA, 0x80) => FrameType::QosData,
            _ => FrameType::Unknown,
        };

        let payload_offset = match ftype {
            FrameType::Data => 24,
            FrameType::QosData => 26,
            _ => 24,
        };

        let payload = if data.len() > payload_offset {
            data[payload_offset..].to_vec()
        } else {
            Vec::new()
        };

        let rssi = self.calculate_rssi(phy_info);
        let channel = (phy_info.channel & 0xFF) as u8;

        Ok(Some(RxFrame {
            frame_type: ftype,
            src_addr,
            dst_addr,
            bssid,
            rssi,
            channel,
            payload,
        }))
    }

    fn calculate_rssi(&self, phy_info: &RxPhyInfo) -> i8 {
        let agc = (phy_info.non_cfg_phy[1] >> 24) as i8;
        -44 - agc
    }

    pub fn extract_data_payload(&self, frame: &RxFrame) -> Option<Vec<u8>> {
        if !matches!(frame.frame_type, FrameType::Data | FrameType::QosData) {
            return None;
        }

        if frame.payload.len() < 8 {
            return None;
        }

        if frame.payload[0..3] == [0xAA, 0xAA, 0x03] {
            Some(frame.payload[8..].to_vec())
        } else {
            Some(frame.payload.clone())
        }
    }
}

pub fn parse_beacon(frame: &RxFrame) -> Option<BeaconInfo> {
    if frame.frame_type != FrameType::Beacon && frame.frame_type != FrameType::ProbeResponse {
        return None;
    }

    if frame.payload.len() < 12 {
        return None;
    }

    let timestamp = u64::from_le_bytes([
        frame.payload[0],
        frame.payload[1],
        frame.payload[2],
        frame.payload[3],
        frame.payload[4],
        frame.payload[5],
        frame.payload[6],
        frame.payload[7],
    ]);
    let beacon_interval = u16::from_le_bytes([frame.payload[8], frame.payload[9]]);
    let capability = u16::from_le_bytes([frame.payload[10], frame.payload[11]]);
    let mut ssid = None;
    let mut channel = None;
    let mut supported_rates = Vec::new();
    let mut is_wpa = false;
    let mut is_wpa2 = false;
    let mut is_wpa3 = false;
    let mut ie_offset = 12;
    while ie_offset + 2 <= frame.payload.len() {
        let ie_id = frame.payload[ie_offset];
        let ie_len = frame.payload[ie_offset + 1] as usize;
        if ie_offset + 2 + ie_len > frame.payload.len() {
            break;
        }

        let ie_data = &frame.payload[ie_offset + 2..ie_offset + 2 + ie_len];

        match ie_id {
            0 => {
                if let Ok(s) = core::str::from_utf8(ie_data) {
                    ssid = Some(s.to_string());
                }
            }
            1 => {
                supported_rates.extend_from_slice(ie_data);
            }
            3 => {
                if !ie_data.is_empty() {
                    channel = Some(ie_data[0]);
                }
            }
            48 => {
                is_wpa2 = true;
                if ie_data.len() >= 4 && ie_data[2..4] == [0x00, 0x0F, 0xAC, 0x08] {
                    is_wpa3 = true;
                }
            }
            221 => {
                if ie_data.len() >= 4 && ie_data[0..4] == [0x00, 0x50, 0xF2, 0x01] {
                    is_wpa = true;
                }
            }
            _ => {}
        }

        ie_offset += 2 + ie_len;
    }

    Some(BeaconInfo {
        bssid: frame.bssid,
        ssid: ssid.unwrap_or_default(),
        channel: channel.unwrap_or(0),
        rssi: frame.rssi,
        timestamp,
        beacon_interval,
        capability,
        is_wpa,
        is_wpa2,
        is_wpa3,
    })
}

#[derive(Debug, Clone)]
pub struct BeaconInfo {
    pub bssid: [u8; 6],
    pub ssid: alloc::string::String,
    pub channel: u8,
    pub rssi: i8,
    pub timestamp: u64,
    pub beacon_interval: u16,
    pub capability: u16,
    pub is_wpa: bool,
    pub is_wpa2: bool,
    pub is_wpa3: bool,
}
