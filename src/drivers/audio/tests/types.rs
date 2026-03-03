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

use super::super::types::*;

#[test]
fn test_bdl_entry_size() {
    assert_eq!(core::mem::size_of::<BdlEntry>(), 16);
}

#[test]
fn test_bdl_entry_new() {
    let entry = BdlEntry::new(0x1234_5678_9ABC_DE80, 4096, true);
    assert_eq!({ entry.addr_lo }, 0x9ABC_DE80);
    assert_eq!({ entry.addr_hi }, 0x1234_5678);
    assert_eq!({ entry.length }, 4096);
    assert_eq!({ entry.flags }, 1);
}

#[test]
fn test_bdl_entry_zeroed() {
    let entry = BdlEntry::zeroed();
    assert_eq!({ entry.addr_lo }, 0);
    assert_eq!({ entry.addr_hi }, 0);
    assert_eq!({ entry.length }, 0);
    assert_eq!({ entry.flags }, 0);
}

#[test]
fn test_bdl_entry_phys_addr() {
    let entry = BdlEntry::new(0xDEAD_BEEF_CAFE_BA80, 512, false);
    assert_eq!(entry.phys_addr(), 0xDEAD_BEEF_CAFE_BA80);
}

#[test]
fn test_audio_stats_default() {
    let stats = AudioStats::default();
    assert_eq!(stats.samples_played, 0);
    assert_eq!(stats.samples_recorded, 0);
    assert_eq!(stats.buffer_underruns, 0);
    assert_eq!(stats.buffer_overruns, 0);
    assert_eq!(stats.interrupts_handled, 0);
    assert_eq!(stats.active_streams, 0);
    assert_eq!(stats.codecs_detected, 0);
}

#[test]
fn test_audio_stats_copy() {
    let stats1 = AudioStats {
        samples_played: 1000,
        samples_recorded: 500,
        buffer_underruns: 2,
        buffer_overruns: 1,
        interrupts_handled: 100,
        active_streams: 1,
        codecs_detected: 2,
        bytes_transferred: 4000,
        error_count: 0,
    };

    let stats2 = stats1;
    assert_eq!(stats1.samples_played, stats2.samples_played);
    assert_eq!(stats1.codecs_detected, stats2.codecs_detected);
}

#[test]
fn test_audio_format_default() {
    let format = AudioFormat::default();
    assert_eq!(format.sample_rate, 48_000);
    assert_eq!(format.bits_per_sample, 16);
    assert_eq!(format.channels, 2);
}

#[test]
fn test_audio_format_bytes_per_sample() {
    let format = AudioFormat::new(48_000, 16, 2);
    assert_eq!(format.bytes_per_sample(), 4);

    let format_mono = AudioFormat::new(44_100, 16, 1);
    assert_eq!(format_mono.bytes_per_sample(), 2);

    let format_24bit = AudioFormat::new(48_000, 24, 2);
    assert_eq!(format_24bit.bytes_per_sample(), 6);
}

#[test]
fn test_audio_format_bytes_per_second() {
    let format = AudioFormat::new(48_000, 16, 2);
    assert_eq!(format.bytes_per_second(), 192_000);
}

#[test]
fn test_audio_format_to_hda() {
    let format = AudioFormat::new(48_000, 16, 2);
    let hda_fmt = format.to_hda_format();
    assert!(hda_fmt.is_some());

    let unsupported = AudioFormat::new(22_050, 16, 2);
    assert!(unsupported.to_hda_format().is_none());
}

#[test]
fn test_stream_state_default() {
    let state = StreamState::default();
    assert_eq!(state, StreamState::Stopped);
}
