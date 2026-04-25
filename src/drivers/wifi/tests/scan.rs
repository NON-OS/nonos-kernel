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

use crate::drivers::wifi::scan::{ScanConfig, ScanResult, SecurityType};
use crate::test::framework::TestResult;
use alloc::string::ToString;

pub(crate) fn test_security_type_open_str() -> TestResult {
    if SecurityType::Open.as_str() != "Open" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_type_wep_str() -> TestResult {
    if SecurityType::Wep.as_str() != "WEP" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_type_wpa_psk_str() -> TestResult {
    if SecurityType::WpaPsk.as_str() != "WPA-PSK" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_type_wpa2_psk_str() -> TestResult {
    if SecurityType::Wpa2Psk.as_str() != "WPA2-PSK" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_type_wpa3_sae_str() -> TestResult {
    if SecurityType::Wpa3Sae.as_str() != "WPA3-SAE" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_type_enterprise_str() -> TestResult {
    if SecurityType::Enterprise.as_str() != "Enterprise" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_type_unknown_str() -> TestResult {
    if SecurityType::Unknown.as_str() != "Unknown" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_type_open_no_password() -> TestResult {
    if SecurityType::Open.requires_password() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_type_wep_requires_password() -> TestResult {
    if !SecurityType::Wep.requires_password() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_type_wpa_psk_requires_password() -> TestResult {
    if !SecurityType::WpaPsk.requires_password() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_type_wpa2_psk_requires_password() -> TestResult {
    if !SecurityType::Wpa2Psk.requires_password() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_type_wpa3_sae_requires_password() -> TestResult {
    if !SecurityType::Wpa3Sae.requires_password() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_type_enterprise_requires_password() -> TestResult {
    if !SecurityType::Enterprise.requires_password() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_type_unknown_requires_password() -> TestResult {
    if !SecurityType::Unknown.requires_password() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_type_equality() -> TestResult {
    if SecurityType::Wpa2Psk != SecurityType::Wpa2Psk {
        return TestResult::Fail;
    }
    if SecurityType::Wpa2Psk == SecurityType::Wpa3Sae {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_type_copy() -> TestResult {
    let sec1 = SecurityType::Wpa3Sae;
    let sec2 = sec1;
    if sec1 != sec2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_type_clone() -> TestResult {
    let sec1 = SecurityType::Enterprise;
    let sec2 = sec1.clone();
    if sec1 != sec2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_result_signal_quality_excellent() -> TestResult {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 6,
        rssi: -45,
        security: SecurityType::Open,
    };
    if result.signal_quality() != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_result_signal_quality_boundary_50() -> TestResult {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 6,
        rssi: -50,
        security: SecurityType::Open,
    };
    if result.signal_quality() != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_result_signal_quality_good() -> TestResult {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 6,
        rssi: -55,
        security: SecurityType::Open,
    };
    if result.signal_quality() != 80 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_result_signal_quality_fair() -> TestResult {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 6,
        rssi: -65,
        security: SecurityType::Open,
    };
    if result.signal_quality() != 60 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_result_signal_quality_weak() -> TestResult {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 6,
        rssi: -75,
        security: SecurityType::Open,
    };
    if result.signal_quality() != 40 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_result_signal_quality_poor() -> TestResult {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 6,
        rssi: -85,
        security: SecurityType::Open,
    };
    if result.signal_quality() != 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_result_signal_quality_none() -> TestResult {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 6,
        rssi: -95,
        security: SecurityType::Open,
    };
    if result.signal_quality() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_result_frequency_2ghz_channel_1() -> TestResult {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 1,
        rssi: -50,
        security: SecurityType::Open,
    };
    if result.frequency_mhz() != 2412 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_result_frequency_2ghz_channel_6() -> TestResult {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 6,
        rssi: -50,
        security: SecurityType::Open,
    };
    if result.frequency_mhz() != 2437 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_result_frequency_2ghz_channel_11() -> TestResult {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 11,
        rssi: -50,
        security: SecurityType::Open,
    };
    if result.frequency_mhz() != 2462 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_result_frequency_5ghz_channel_36() -> TestResult {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 36,
        rssi: -50,
        security: SecurityType::Open,
    };
    if result.frequency_mhz() != 5180 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_result_frequency_5ghz_channel_149() -> TestResult {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 149,
        rssi: -50,
        security: SecurityType::Open,
    };
    if result.frequency_mhz() != 5745 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_result_band_2ghz() -> TestResult {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 6,
        rssi: -50,
        security: SecurityType::Open,
    };
    if result.band() != "2.4 GHz" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_result_band_5ghz() -> TestResult {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 36,
        rssi: -50,
        security: SecurityType::Open,
    };
    if result.band() != "5 GHz" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_result_band_6ghz() -> TestResult {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 200,
        rssi: -50,
        security: SecurityType::Open,
    };
    if result.band() != "6 GHz" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_config_default_has_channels() -> TestResult {
    let cfg = ScanConfig::default();
    if cfg.channels.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_config_default_dwell_active() -> TestResult {
    let cfg = ScanConfig::default();
    if cfg.dwell_time_active != 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_config_default_dwell_passive() -> TestResult {
    let cfg = ScanConfig::default();
    if cfg.dwell_time_passive != 110 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_config_default_not_passive() -> TestResult {
    let cfg = ScanConfig::default();
    if cfg.passive_scan {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_config_default_no_ssid_filter() -> TestResult {
    let cfg = ScanConfig::default();
    if cfg.ssid_filter.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_config_2ghz_only_channels() -> TestResult {
    let cfg = ScanConfig::new_2ghz_only();
    if cfg.channels.len() != 13 {
        return TestResult::Fail;
    }
    if !cfg.channels.contains(&1) {
        return TestResult::Fail;
    }
    if !cfg.channels.contains(&13) {
        return TestResult::Fail;
    }
    if cfg.channels.contains(&36) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_config_5ghz_only_channels() -> TestResult {
    let cfg = ScanConfig::new_5ghz_only();
    if !cfg.channels.contains(&36) {
        return TestResult::Fail;
    }
    if !cfg.channels.contains(&165) {
        return TestResult::Fail;
    }
    if cfg.channels.contains(&1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_config_with_ssid() -> TestResult {
    let cfg = ScanConfig::default().with_ssid("MyNetwork");
    if cfg.ssid_filter != Some("MyNetwork".to_string()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_config_with_passive() -> TestResult {
    let cfg = ScanConfig::default().with_passive();
    if !cfg.passive_scan {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_config_builder_chain() -> TestResult {
    let cfg = ScanConfig::new_2ghz_only().with_ssid("Test").with_passive();
    if cfg.channels.len() != 13 {
        return TestResult::Fail;
    }
    if cfg.ssid_filter != Some("Test".to_string()) {
        return TestResult::Fail;
    }
    if !cfg.passive_scan {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_result_clone() -> TestResult {
    let result = ScanResult {
        ssid: "TestNetwork".to_string(),
        bssid: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        channel: 6,
        rssi: -60,
        security: SecurityType::Wpa2Psk,
    };
    let cloned = result.clone();
    if result.ssid != cloned.ssid {
        return TestResult::Fail;
    }
    if result.bssid != cloned.bssid {
        return TestResult::Fail;
    }
    if result.channel != cloned.channel {
        return TestResult::Fail;
    }
    if result.rssi != cloned.rssi {
        return TestResult::Fail;
    }
    if result.security != cloned.security {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scan_config_clone() -> TestResult {
    let cfg = ScanConfig::default().with_ssid("Test");
    let cloned = cfg.clone();
    if cfg.channels != cloned.channels {
        return TestResult::Fail;
    }
    if cfg.ssid_filter != cloned.ssid_filter {
        return TestResult::Fail;
    }
    TestResult::Pass
}
