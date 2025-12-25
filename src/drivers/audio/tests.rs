// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//
//! Unit tests for the HD Audio driver module.

use super::*;
use super::constants::*;
use super::types::*;
use super::error::*;
use super::controller::{vendor_name, Capabilities, compose_verb};

// =============================================================================
// Error Type Tests
// =============================================================================

#[test]
fn test_audio_error_display() {
    assert_eq!(AudioError::Bar0NotMmio.as_str(), "HDA BAR0 is not MMIO");
    assert_eq!(AudioError::NoControllerFound.as_str(), "No HD Audio controller found");
    assert_eq!(AudioError::PlaybackTimeout.as_str(), "Playback did not complete in time");
    assert_eq!(AudioError::UnsupportedFormat.as_str(), "Unsupported PCM format");
}

#[test]
fn test_audio_error_variants() {
    let errors = [
        AudioError::Bar0NotMmio,
        AudioError::CrstClearTimeout,
        AudioError::CrstSetTimeout,
        AudioError::DmaAllocationFailed,
        AudioError::NoControllerFound,
        AudioError::NoCodecPresent,
        AudioError::ImmediateCmdBusy,
        AudioError::ImmediateResponseTimeout,
        AudioError::CorbRirbTimeout,
        AudioError::StreamResetSetTimeout,
        AudioError::StreamResetClearTimeout,
        AudioError::UnsupportedFormat,
        AudioError::PlaybackTimeout,
        AudioError::NotInitialized,
        AudioError::StreamNotConfigured,
        AudioError::InvalidStreamIndex,
        AudioError::BufferTooLarge,
        AudioError::CodecInitFailed,
    ];

    // Verify count matches enum variants
    assert_eq!(errors.len(), 18);

    // Verify each has a non-empty description
    for err in &errors {
        assert!(!err.as_str().is_empty());
    }
}

#[test]
fn test_audio_error_equality() {
    assert_eq!(AudioError::Bar0NotMmio, AudioError::Bar0NotMmio);
    assert_ne!(AudioError::Bar0NotMmio, AudioError::NoControllerFound);

    // Test Copy trait
    let err1 = AudioError::PlaybackTimeout;
    let err2 = err1;
    assert_eq!(err1, err2);
}

#[test]
fn test_audio_error_from_str() {
    let err: AudioError = "HDA BAR0 is not MMIO".into();
    assert_eq!(err, AudioError::Bar0NotMmio);

    let err: AudioError = "No HD Audio controller found".into();
    assert_eq!(err, AudioError::NoControllerFound);

    // Unknown strings should map to NotInitialized as fallback
    let err: AudioError = "Unknown error".into();
    assert_eq!(err, AudioError::NotInitialized);
}

// =============================================================================
// Constants Tests
// =============================================================================

#[test]
fn test_global_register_offsets() {
    // Verify global register offsets per HDA spec
    assert_eq!(GCAP, 0x00);
    assert_eq!(VMIN, 0x02);
    assert_eq!(VMAJ, 0x03);
    assert_eq!(GCTL, 0x08);
    assert_eq!(STATESTS, 0x0E);
    assert_eq!(INTCTL, 0x20);
    assert_eq!(INTSTS, 0x24);
}

#[test]
fn test_corb_rirb_offsets() {
    assert_eq!(CORBLBASE, 0x40);
    assert_eq!(CORBUBASE, 0x44);
    assert_eq!(CORBWP, 0x48);
    assert_eq!(CORBRP, 0x4A);
    assert_eq!(CORBCTL, 0x4C);
    assert_eq!(RIRBLBASE, 0x50);
    assert_eq!(RIRBUBASE, 0x54);
    assert_eq!(RIRBWP, 0x58);
    assert_eq!(RIRBCTL, 0x5C);
}

#[test]
fn test_immediate_command_offsets() {
    assert_eq!(IC, 0x60);
    assert_eq!(IR, 0x64);
    assert_eq!(IRS, 0x68);
}

#[test]
fn test_stream_descriptor_offsets() {
    assert_eq!(STREAM_BASE, 0x80);
    assert_eq!(STREAM_STRIDE, 0x20);
    assert_eq!(SD_CTL, 0x00);
    assert_eq!(SD_LPIB, 0x04);
    assert_eq!(SD_CBL, 0x08);
    assert_eq!(SD_LVI, 0x0C);
    assert_eq!(SD_FMT, 0x12);
    assert_eq!(SD_BDPL, 0x18);
    assert_eq!(SD_BDPU, 0x1C);
}

#[test]
fn test_gctl_bits() {
    assert_eq!(GCTL_CRST, 1 << 0);
    assert_eq!(GCTL_FCNTRL, 1 << 1);
    assert_eq!(GCTL_UNSOL, 1 << 8);
}

#[test]
fn test_stream_ctl_bits() {
    assert_eq!(SD_CTL_SRST, 1 << 0);
    assert_eq!(SD_CTL_RUN, 1 << 1);
    assert_eq!(SD_CTL_IOCE, 1 << 2);
    assert_eq!(SD_CTL_FEIE, 1 << 3);
    assert_eq!(SD_CTL_DEIE, 1 << 4);
}

#[test]
fn test_buffer_sizes() {
    assert_eq!(CORB_ENTRIES, 256);
    assert_eq!(RIRB_ENTRIES, 256);
    assert_eq!(CORB_SIZE, 256 * 4);
    assert_eq!(RIRB_SIZE, 256 * 8);
    assert_eq!(BDL_ENTRIES, 16);
    assert_eq!(PCM_BUFFER_SIZE, 64 * 1024);
}

#[test]
fn test_default_audio_constants() {
    assert_eq!(DEFAULT_SAMPLE_RATE, 48_000);
    assert_eq!(DEFAULT_BITS_PER_SAMPLE, 16);
    assert_eq!(DEFAULT_CHANNELS, 2);
}

// =============================================================================
// Types Tests
// =============================================================================

#[test]
fn test_bdl_entry_size() {
    // BDL entry must be exactly 16 bytes per HDA spec
    assert_eq!(core::mem::size_of::<BdlEntry>(), 16);
}

#[test]
fn test_bdl_entry_new() {
    let entry = BdlEntry::new(0x1234_5678_9ABC_DEF0, 4096, true);
    // Use block syntax to copy packed fields (avoids unaligned reference)
    assert_eq!({ entry.addr_lo }, 0x9ABC_DEF0);
    assert_eq!({ entry.addr_hi }, 0x1234_5678);
    assert_eq!({ entry.length }, 4096);
    assert_eq!({ entry.flags }, 1); // IOC set
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
    let entry = BdlEntry::new(0xDEAD_BEEF_CAFE_BABE, 512, false);
    assert_eq!(entry.phys_addr(), 0xDEAD_BEEF_CAFE_BABE);
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
    assert_eq!(format.bytes_per_sample(), 4); // 16 bits / 8 * 2 channels

    let format_mono = AudioFormat::new(44_100, 16, 1);
    assert_eq!(format_mono.bytes_per_sample(), 2);

    let format_24bit = AudioFormat::new(48_000, 24, 2);
    assert_eq!(format_24bit.bytes_per_sample(), 6); // 24 / 8 * 2
}

#[test]
fn test_audio_format_bytes_per_second() {
    let format = AudioFormat::new(48_000, 16, 2);
    // 48000 samples/sec * 4 bytes/sample = 192000 bytes/sec
    assert_eq!(format.bytes_per_second(), 192_000);
}

#[test]
fn test_audio_format_to_hda() {
    let format = AudioFormat::new(48_000, 16, 2);
    let hda_fmt = format.to_hda_format();
    assert!(hda_fmt.is_some());

    // Unsupported format
    let unsupported = AudioFormat::new(44_100, 16, 2);
    assert!(unsupported.to_hda_format().is_none());
}

#[test]
fn test_stream_state_default() {
    let state = StreamState::default();
    assert_eq!(state, StreamState::Stopped);
}

// =============================================================================
// Controller Helper Tests
// =============================================================================

#[test]
fn test_compose_verb() {
    // CAD=0, NID=0, Verb=0xF00 (GetParameter), Param=0x00 (VendorID)
    let verb = compose_verb(0, 0, 0xF00, 0x00);
    assert_eq!(verb, 0x000F_0000);

    // CAD=1, NID=2, Verb=0x705 (SetPowerState), Payload=0x00 (D0)
    // Formula: (cad << 28) | (nid << 20) | (verb << 8) | payload
    // = 0x10000000 | 0x00200000 | 0x00070500 | 0x00 = 0x10270500
    let verb = compose_verb(1, 2, 0x705, 0x00);
    assert_eq!(verb, 0x1027_0500);
}

#[test]
fn test_capabilities_from_gcap() {
    // GCAP with 4 OSS, 2 ISS, 1 BSS, 64-bit capable
    // Bits: OSS[15:12]=4, ISS[11:8]=2, BSS[7:3]=1, 64bit[0]=1
    let gcap = (4 << 12) | (2 << 8) | (1 << 3) | 1;
    let caps = Capabilities::from_gcap(gcap);

    assert_eq!(caps.output_streams, 4);
    assert_eq!(caps.input_streams, 2);
    assert_eq!(caps.bidi_streams, 1);
    assert!(caps.addr64);
    assert_eq!(caps.total_streams(), 7);
}

#[test]
fn test_vendor_name() {
    assert_eq!(vendor_name(0x8086), "Intel");
    assert_eq!(vendor_name(0x10DE), "NVIDIA");
    assert_eq!(vendor_name(0x1002), "AMD/ATI");
    assert_eq!(vendor_name(0x10EC), "Realtek");
    assert_eq!(vendor_name(0x14F1), "Conexant");
    assert_eq!(vendor_name(0x1106), "VIA");
    assert_eq!(vendor_name(0x1AF4), "VirtIO");
    assert_eq!(vendor_name(0x0000), "Unknown");
}

// =============================================================================
// Timing Constants Tests
// =============================================================================

#[test]
fn test_spin_timeouts() {
    assert!(SPIN_TIMEOUT_DEFAULT > 0);
    assert!(SPIN_TIMEOUT_SHORT > 0);
    assert!(SPIN_TIMEOUT_LONG > 0);
    assert!(SPIN_TIMEOUT_SHORT < SPIN_TIMEOUT_DEFAULT);
    assert!(SPIN_TIMEOUT_DEFAULT < SPIN_TIMEOUT_LONG);
}

// =============================================================================
// PCI Constants Tests
// =============================================================================

#[test]
fn test_pci_class_codes() {
    assert_eq!(HDA_CLASS, 0x04);    // Multimedia controller
    assert_eq!(HDA_SUBCLASS, 0x03); // HD Audio
}
