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

use super::*;

#[test]
fn test_bdl_entry_size() {
    assert_eq!(core::mem::size_of::<BdlEntry>(), 16);
}

#[test]
fn test_bdl_entry_new() {
    let entry = BdlEntry::new(0x1234_5678_9ABC_DE00, 4096, true);
    assert_eq!(entry.phys_addr(), 0x1234_5678_9ABC_DE00);
    assert_eq!(entry.len(), 4096);
    assert!(entry.has_ioc());
    assert!(entry.is_valid());
}

#[test]
fn test_bdl_entry_zeroed() {
    let entry = BdlEntry::zeroed();
    assert_eq!(entry.phys_addr(), 0);
    assert_eq!(entry.len(), 0);
    assert!(!entry.has_ioc());
    assert!(!entry.is_valid());
}

#[test]
fn test_audio_format_default() {
    let format = AudioFormat::default();
    assert_eq!(format.sample_rate, 48_000);
    assert_eq!(format.bits_per_sample, 16);
    assert_eq!(format.channels, 2);
    assert!(format.is_valid());
    assert!(format.is_supported());
}

#[test]
fn test_audio_format_bytes() {
    let format = AudioFormat::default();
    assert_eq!(format.bytes_per_sample(), 4);
    assert_eq!(format.bytes_per_second(), 192_000);
}

#[test]
fn test_audio_format_conversion() {
    let format = AudioFormat::default();
    let hw_fmt = format.to_hda_format().unwrap();
    let decoded = AudioFormat::from_hda_format(hw_fmt).unwrap();
    assert_eq!(format.sample_rate, decoded.sample_rate);
    assert_eq!(format.bits_per_sample, decoded.bits_per_sample);
    assert_eq!(format.channels, decoded.channels);
}

#[test]
fn test_stream_state_transitions() {
    assert!(StreamState::Stopped.can_start());
    assert!(StreamState::Ready.can_start());
    assert!(!StreamState::Running.can_start());
    assert!(StreamState::Running.can_stop());
    assert!(StreamState::Running.is_active());
    assert!(!StreamState::Stopped.is_active());
}

#[test]
fn test_volume() {
    assert_eq!(Volume::MIN.percent(), 0);
    assert_eq!(Volume::MAX.percent(), 100);
    assert!(Volume::MIN.is_muted());
    assert!(!Volume::MAX.is_muted());
    assert_eq!(Volume::new(150).percent(), 100);
    assert_eq!(Volume::MAX.to_gain(), 127);
    assert_eq!(Volume::MIN.to_gain(), 0);
}

#[test]
fn test_audio_stats() {
    let stats = AudioStats::new();
    assert!(!stats.has_errors());
    assert_eq!(stats.total_errors(), 0);

    let stats_with_errors = AudioStats {
        buffer_underruns: 5,
        ..AudioStats::new()
    };
    assert!(stats_with_errors.has_errors());
    assert_eq!(stats_with_errors.total_errors(), 5);
}
