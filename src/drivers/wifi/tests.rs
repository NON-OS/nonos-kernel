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

use super::rx::{FrameType, RxProcessor};
use super::scan::{filter_by_security, ScanConfig, ScanResult, SecurityType, sort_by_signal};
use super::tx::{calculate_tx_time, select_tx_rate, Ieee80211Header};
use super::*;

#[test]
fn test_scan_config_default() {
    let cfg = ScanConfig::default();
    assert!(!cfg.channels.is_empty());
    assert!(cfg.channels.contains(&1));
    assert!(cfg.channels.contains(&6));
    assert!(cfg.channels.contains(&36));
    assert_eq!(cfg.dwell_time_active, 20);
    assert!(!cfg.passive_scan);
}

#[test]
fn test_scan_config_2ghz() {
    let cfg = ScanConfig::new_2ghz_only();
    assert!(cfg.channels.iter().all(|&ch| ch <= 14));
    assert!(!cfg.channels.contains(&36));
}

#[test]
fn test_scan_config_5ghz() {
    let cfg = ScanConfig::new_5ghz_only();
    assert!(cfg.channels.iter().all(|&ch| ch >= 36));
    assert!(!cfg.channels.contains(&1));
}

#[test]
fn test_scan_result_signal_quality() {
    let result = ScanResult {
        ssid: "Test".into(),
        bssid: [0; 6],
        channel: 6,
        rssi: -50,
        security: SecurityType::Open,
    };
    assert_eq!(result.signal_quality(), 100);

    let result2 = ScanResult {
        rssi: -75,
        ..result.clone()
    };
    assert_eq!(result2.signal_quality(), 40);

    let result3 = ScanResult { rssi: -95, ..result };
    assert_eq!(result3.signal_quality(), 0);
}

#[test]
fn test_scan_result_frequency() {
    let result = ScanResult {
        ssid: String::new(),
        bssid: [0; 6],
        channel: 6,
        rssi: -60,
        security: SecurityType::Open,
    };
    assert_eq!(result.frequency_mhz(), 2437);
    assert_eq!(result.band(), "2.4 GHz");

    let result_5g = ScanResult {
        channel: 36,
        ..result
    };
    assert_eq!(result_5g.frequency_mhz(), 5180);
    assert_eq!(result_5g.band(), "5 GHz");
}

#[test]
fn test_sort_by_signal() {
    let mut results = vec![
        ScanResult {
            ssid: "A".into(),
            bssid: [0; 6],
            channel: 1,
            rssi: -70,
            security: SecurityType::Open,
        },
        ScanResult {
            ssid: "B".into(),
            bssid: [0; 6],
            channel: 1,
            rssi: -50,
            security: SecurityType::Open,
        },
        ScanResult {
            ssid: "C".into(),
            bssid: [0; 6],
            channel: 1,
            rssi: -60,
            security: SecurityType::Open,
        },
    ];

    sort_by_signal(&mut results);

    assert_eq!(results[0].ssid, "B");
    assert_eq!(results[1].ssid, "C");
    assert_eq!(results[2].ssid, "A");
}

#[test]
fn test_filter_by_security() {
    let results = vec![
        ScanResult {
            ssid: "Open".into(),
            bssid: [0; 6],
            channel: 1,
            rssi: -60,
            security: SecurityType::Open,
        },
        ScanResult {
            ssid: "WPA2".into(),
            bssid: [0; 6],
            channel: 1,
            rssi: -60,
            security: SecurityType::Wpa2Psk,
        },
        ScanResult {
            ssid: "WPA3".into(),
            bssid: [0; 6],
            channel: 1,
            rssi: -60,
            security: SecurityType::Wpa3Sae,
        },
    ];

    let wpa2_only = filter_by_security(&results, SecurityType::Wpa2Psk);
    assert_eq!(wpa2_only.len(), 1);
    assert_eq!(wpa2_only[0].ssid, "WPA2");
}

#[test]
fn test_security_type() {
    assert!(!SecurityType::Open.requires_password());
    assert!(SecurityType::Wpa2Psk.requires_password());
    assert!(SecurityType::Wpa3Sae.requires_password());
    assert_eq!(SecurityType::Wpa2Psk.as_str(), "WPA2-PSK");
}

#[test]
fn test_tx_time_calculation() {
    let time = calculate_tx_time(54, 1500);
    assert!(time > 0);
    assert!(time < 1000);

    let time_zero = calculate_tx_time(0, 1500);
    assert_eq!(time_zero, 0);
}

#[test]
fn test_tx_rate_selection() {
    let rate = select_tx_rate(-50, true);
    assert_eq!(rate, 866);

    let rate_weak = select_tx_rate(-85, true);
    assert_eq!(rate_weak, 24);

    let rate_2g = select_tx_rate(-50, false);
    assert_eq!(rate_2g, 130);
}

#[test]
fn test_ieee80211_header() {
    let bssid = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let src = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let dst = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];

    let header = Ieee80211Header::new_data(&bssid, &src, &dst, 1);

    assert_eq!(header.addr1, bssid);
    assert_eq!(header.addr2, src);
    assert_eq!(header.addr3, dst);
    assert_eq!(header.seq_ctrl, 1 << 4);
}

#[test]
fn test_rx_processor() {
    let mut processor = RxProcessor::new();
    assert_eq!(processor.promiscuous, false);

    processor.set_promiscuous(true);
    assert_eq!(processor.promiscuous, true);

    let bssid = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    processor.set_bssid_filter(Some(bssid));
}

#[test]
fn test_wifi_error() {
    let err = WifiError::NotInitialized;
    assert_eq!(err.code(), 0x0001);
    assert_eq!(err.as_str(), "WiFi not initialized");

    let err2 = WifiError::FirmwareInvalid;
    assert_eq!(err2.code(), 0x0004);
}

#[test]
fn test_device_ids() {
    assert!(SUPPORTED_DEVICE_IDS.contains(&0x2723));
    assert!(SUPPORTED_DEVICE_IDS.contains(&0x24F3));
    assert!(SUPPORTED_DEVICE_IDS.contains(&0x08B1));
    assert!(!SUPPORTED_DEVICE_IDS.contains(&0x0000));
}

#[test]
fn test_wifi_state() {
    let state = WifiState::Ready;
    assert_eq!(state, WifiState::Ready);
    assert_ne!(state, WifiState::Connected);
}
