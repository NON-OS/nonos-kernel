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

use alloc::string::ToString;
use crate::drivers::wifi::scan::{ScanConfig, ScanResult, SecurityType};

#[test]
fn test_security_type_open_str() {
    assert_eq!(SecurityType::Open.as_str(), "Open");
}

#[test]
fn test_security_type_wep_str() {
    assert_eq!(SecurityType::Wep.as_str(), "WEP");
}

#[test]
fn test_security_type_wpa_psk_str() {
    assert_eq!(SecurityType::WpaPsk.as_str(), "WPA-PSK");
}

#[test]
fn test_security_type_wpa2_psk_str() {
    assert_eq!(SecurityType::Wpa2Psk.as_str(), "WPA2-PSK");
}

#[test]
fn test_security_type_wpa3_sae_str() {
    assert_eq!(SecurityType::Wpa3Sae.as_str(), "WPA3-SAE");
}

#[test]
fn test_security_type_enterprise_str() {
    assert_eq!(SecurityType::Enterprise.as_str(), "Enterprise");
}

#[test]
fn test_security_type_unknown_str() {
    assert_eq!(SecurityType::Unknown.as_str(), "Unknown");
}

#[test]
fn test_security_type_open_no_password() {
    assert!(!SecurityType::Open.requires_password());
}

#[test]
fn test_security_type_wep_requires_password() {
    assert!(SecurityType::Wep.requires_password());
}

#[test]
fn test_security_type_wpa_psk_requires_password() {
    assert!(SecurityType::WpaPsk.requires_password());
}

#[test]
fn test_security_type_wpa2_psk_requires_password() {
    assert!(SecurityType::Wpa2Psk.requires_password());
}

#[test]
fn test_security_type_wpa3_sae_requires_password() {
    assert!(SecurityType::Wpa3Sae.requires_password());
}

#[test]
fn test_security_type_enterprise_requires_password() {
    assert!(SecurityType::Enterprise.requires_password());
}

#[test]
fn test_security_type_unknown_requires_password() {
    assert!(SecurityType::Unknown.requires_password());
}

#[test]
fn test_security_type_equality() {
    assert_eq!(SecurityType::Wpa2Psk, SecurityType::Wpa2Psk);
    assert_ne!(SecurityType::Wpa2Psk, SecurityType::Wpa3Sae);
}

#[test]
fn test_security_type_copy() {
    let sec1 = SecurityType::Wpa3Sae;
    let sec2 = sec1;
    assert_eq!(sec1, sec2);
}

#[test]
fn test_security_type_clone() {
    let sec1 = SecurityType::Enterprise;
    let sec2 = sec1.clone();
    assert_eq!(sec1, sec2);
}

#[test]
fn test_scan_result_signal_quality_excellent() {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 6,
        rssi: -45,
        security: SecurityType::Open,
    };
    assert_eq!(result.signal_quality(), 100);
}

#[test]
fn test_scan_result_signal_quality_boundary_50() {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 6,
        rssi: -50,
        security: SecurityType::Open,
    };
    assert_eq!(result.signal_quality(), 100);
}

#[test]
fn test_scan_result_signal_quality_good() {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 6,
        rssi: -55,
        security: SecurityType::Open,
    };
    assert_eq!(result.signal_quality(), 80);
}

#[test]
fn test_scan_result_signal_quality_fair() {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 6,
        rssi: -65,
        security: SecurityType::Open,
    };
    assert_eq!(result.signal_quality(), 60);
}

#[test]
fn test_scan_result_signal_quality_weak() {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 6,
        rssi: -75,
        security: SecurityType::Open,
    };
    assert_eq!(result.signal_quality(), 40);
}

#[test]
fn test_scan_result_signal_quality_poor() {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 6,
        rssi: -85,
        security: SecurityType::Open,
    };
    assert_eq!(result.signal_quality(), 20);
}

#[test]
fn test_scan_result_signal_quality_none() {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 6,
        rssi: -95,
        security: SecurityType::Open,
    };
    assert_eq!(result.signal_quality(), 0);
}

#[test]
fn test_scan_result_frequency_2ghz_channel_1() {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 1,
        rssi: -50,
        security: SecurityType::Open,
    };
    assert_eq!(result.frequency_mhz(), 2412);
}

#[test]
fn test_scan_result_frequency_2ghz_channel_6() {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 6,
        rssi: -50,
        security: SecurityType::Open,
    };
    assert_eq!(result.frequency_mhz(), 2437);
}

#[test]
fn test_scan_result_frequency_2ghz_channel_11() {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 11,
        rssi: -50,
        security: SecurityType::Open,
    };
    assert_eq!(result.frequency_mhz(), 2462);
}

#[test]
fn test_scan_result_frequency_5ghz_channel_36() {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 36,
        rssi: -50,
        security: SecurityType::Open,
    };
    assert_eq!(result.frequency_mhz(), 5180);
}

#[test]
fn test_scan_result_frequency_5ghz_channel_149() {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 149,
        rssi: -50,
        security: SecurityType::Open,
    };
    assert_eq!(result.frequency_mhz(), 5745);
}

#[test]
fn test_scan_result_band_2ghz() {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 6,
        rssi: -50,
        security: SecurityType::Open,
    };
    assert_eq!(result.band(), "2.4 GHz");
}

#[test]
fn test_scan_result_band_5ghz() {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 36,
        rssi: -50,
        security: SecurityType::Open,
    };
    assert_eq!(result.band(), "5 GHz");
}

#[test]
fn test_scan_result_band_6ghz() {
    let result = ScanResult {
        ssid: "Test".to_string(),
        bssid: [0x00; 6],
        channel: 200,
        rssi: -50,
        security: SecurityType::Open,
    };
    assert_eq!(result.band(), "6 GHz");
}

#[test]
fn test_scan_config_default_has_channels() {
    let cfg = ScanConfig::default();
    assert!(!cfg.channels.is_empty());
}

#[test]
fn test_scan_config_default_dwell_active() {
    let cfg = ScanConfig::default();
    assert_eq!(cfg.dwell_time_active, 20);
}

#[test]
fn test_scan_config_default_dwell_passive() {
    let cfg = ScanConfig::default();
    assert_eq!(cfg.dwell_time_passive, 110);
}

#[test]
fn test_scan_config_default_not_passive() {
    let cfg = ScanConfig::default();
    assert!(!cfg.passive_scan);
}

#[test]
fn test_scan_config_default_no_ssid_filter() {
    let cfg = ScanConfig::default();
    assert!(cfg.ssid_filter.is_none());
}

#[test]
fn test_scan_config_2ghz_only_channels() {
    let cfg = ScanConfig::new_2ghz_only();
    assert_eq!(cfg.channels.len(), 13);
    assert!(cfg.channels.contains(&1));
    assert!(cfg.channels.contains(&13));
    assert!(!cfg.channels.contains(&36));
}

#[test]
fn test_scan_config_5ghz_only_channels() {
    let cfg = ScanConfig::new_5ghz_only();
    assert!(cfg.channels.contains(&36));
    assert!(cfg.channels.contains(&165));
    assert!(!cfg.channels.contains(&1));
}

#[test]
fn test_scan_config_with_ssid() {
    let cfg = ScanConfig::default().with_ssid("MyNetwork");
    assert_eq!(cfg.ssid_filter, Some("MyNetwork".to_string()));
}

#[test]
fn test_scan_config_with_passive() {
    let cfg = ScanConfig::default().with_passive();
    assert!(cfg.passive_scan);
}

#[test]
fn test_scan_config_builder_chain() {
    let cfg = ScanConfig::new_2ghz_only()
        .with_ssid("Test")
        .with_passive();
    assert_eq!(cfg.channels.len(), 13);
    assert_eq!(cfg.ssid_filter, Some("Test".to_string()));
    assert!(cfg.passive_scan);
}

#[test]
fn test_scan_result_clone() {
    let result = ScanResult {
        ssid: "TestNetwork".to_string(),
        bssid: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        channel: 6,
        rssi: -60,
        security: SecurityType::Wpa2Psk,
    };
    let cloned = result.clone();
    assert_eq!(result.ssid, cloned.ssid);
    assert_eq!(result.bssid, cloned.bssid);
    assert_eq!(result.channel, cloned.channel);
    assert_eq!(result.rssi, cloned.rssi);
    assert_eq!(result.security, cloned.security);
}

#[test]
fn test_scan_config_clone() {
    let cfg = ScanConfig::default().with_ssid("Test");
    let cloned = cfg.clone();
    assert_eq!(cfg.channels, cloned.channels);
    assert_eq!(cfg.ssid_filter, cloned.ssid_filter);
}
