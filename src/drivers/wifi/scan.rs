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

use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityType {
    Open,
    Wep,
    WpaPsk,
    Wpa2Psk,
    Wpa3Sae,
    Enterprise,
    Unknown,
}

impl SecurityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityType::Open => "Open",
            SecurityType::Wep => "WEP",
            SecurityType::WpaPsk => "WPA-PSK",
            SecurityType::Wpa2Psk => "WPA2-PSK",
            SecurityType::Wpa3Sae => "WPA3-SAE",
            SecurityType::Enterprise => "Enterprise",
            SecurityType::Unknown => "Unknown",
        }
    }

    pub fn requires_password(&self) -> bool {
        !matches!(self, SecurityType::Open)
    }
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub ssid: String,
    pub bssid: [u8; 6],
    pub channel: u8,
    pub rssi: i8,
    pub security: SecurityType,
}

impl ScanResult {
    pub fn signal_quality(&self) -> u8 {
        if self.rssi >= -50 {
            100
        } else if self.rssi >= -60 {
            80
        } else if self.rssi >= -70 {
            60
        } else if self.rssi >= -80 {
            40
        } else if self.rssi >= -90 {
            20
        } else {
            0
        }
    }

    pub fn frequency_mhz(&self) -> u32 {
        if self.channel <= 14 {
            2407 + (self.channel as u32 * 5)
        } else if self.channel >= 36 && self.channel <= 177 {
            5000 + (self.channel as u32 * 5)
        } else if self.channel >= 1 && self.channel <= 233 {
            5950 + (self.channel as u32 * 5)
        } else {
            0
        }
    }

    pub fn band(&self) -> &'static str {
        if self.channel <= 14 {
            "2.4 GHz"
        } else if self.channel >= 36 && self.channel <= 177 {
            "5 GHz"
        } else {
            "6 GHz"
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub channels: Vec<u8>,
    pub dwell_time_active: u16,
    pub dwell_time_passive: u16,
    pub passive_scan: bool,
    pub ssid_filter: Option<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        let mut channels = Vec::new();

        for ch in 1..=13 {
            channels.push(ch);
        }

        for ch in [
            36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
            144, 149, 153, 157, 161, 165,
        ] {
            channels.push(ch);
        }

        Self {
            channels,
            dwell_time_active: 20,
            dwell_time_passive: 110,
            passive_scan: false,
            ssid_filter: None,
        }
    }
}

impl ScanConfig {
    pub fn new_2ghz_only() -> Self {
        let mut cfg = Self::default();
        cfg.channels = (1..=13).collect();
        cfg
    }

    pub fn new_5ghz_only() -> Self {
        Self {
            channels: vec![
                36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136,
                140, 144, 149, 153, 157, 161, 165,
            ],
            ..Default::default()
        }
    }

    pub fn with_ssid(mut self, ssid: &str) -> Self {
        self.ssid_filter = Some(ssid.to_string());
        self
    }

    pub fn with_passive(mut self) -> Self {
        self.passive_scan = true;
        self
    }
}

pub fn sort_by_signal(results: &mut [ScanResult]) {
    results.sort_by(|a, b| b.rssi.cmp(&a.rssi));
}

pub fn filter_by_security(results: &[ScanResult], security: SecurityType) -> Vec<ScanResult> {
    results
        .iter()
        .filter(|r| r.security == security)
        .cloned()
        .collect()
}

pub fn find_network<'a>(results: &'a [ScanResult], ssid: &str) -> Option<&'a ScanResult> {
    results.iter().find(|r| r.ssid == ssid)
}
