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
//! Intel HD Audio register constants and bit definitions.
//!
//! Reference: Intel High Definition Audio Specification, Revision 1.0a

// =============================================================================
// PCI Class/Subclass
// =============================================================================

/// PCI class code for multimedia devices
pub const HDA_CLASS: u8 = 0x04;
/// PCI subclass for HD Audio controllers
pub const HDA_SUBCLASS: u8 = 0x03;

// =============================================================================
// Global Registers (Section 4.2)
// =============================================================================

/// Global Capabilities (16-bit, RO)
pub const GCAP: usize = 0x00;
/// Minor Version (8-bit, RO)
pub const VMIN: usize = 0x02;
/// Major Version (8-bit, RO)
pub const VMAJ: usize = 0x03;
/// Output Payload Capability (16-bit, RO)
pub const OUTPAY: usize = 0x04;
/// Input Payload Capability (16-bit, RO)
pub const INPAY: usize = 0x06;
/// Global Control (32-bit, RW)
pub const GCTL: usize = 0x08;
/// Wake Enable (16-bit, RW)
pub const WAKEEN: usize = 0x0C;
/// State Change Status (16-bit, RW1C)
pub const STATESTS: usize = 0x0E;
/// Global Status (16-bit, RO)
pub const GSTS: usize = 0x10;
/// Interrupt Control (32-bit, RW)
pub const INTCTL: usize = 0x20;
/// Interrupt Status (32-bit, RO)
pub const INTSTS: usize = 0x24;
/// Wall Clock Counter (32-bit, RO)
pub const WALCLK: usize = 0x30;
/// Stream Synchronization (32-bit, RW)
pub const SSYNC: usize = 0x34;

// =============================================================================
// CORB Registers (Section 4.3)
// =============================================================================

/// CORB Lower Base Address (32-bit, RW)
pub const CORBLBASE: usize = 0x40;
/// CORB Upper Base Address (32-bit, RW)
pub const CORBUBASE: usize = 0x44;
/// CORB Write Pointer (16-bit, RW)
pub const CORBWP: usize = 0x48;
/// CORB Read Pointer (16-bit, RW)
pub const CORBRP: usize = 0x4A;
/// CORB Control (8-bit, RW)
pub const CORBCTL: usize = 0x4C;
/// CORB Status (8-bit, RW1C)
pub const CORBSTS: usize = 0x4D;
/// CORB Size (8-bit, RW)
pub const CORBSIZE: usize = 0x4E;

// =============================================================================
// RIRB Registers (Section 4.4)
// =============================================================================

/// RIRB Lower Base Address (32-bit, RW)
pub const RIRBLBASE: usize = 0x50;
/// RIRB Upper Base Address (32-bit, RW)
pub const RIRBUBASE: usize = 0x54;
/// RIRB Write Pointer (16-bit, RO)
pub const RIRBWP: usize = 0x58;
/// Response Interrupt Count (16-bit, RW)
pub const RINTCNT: usize = 0x5A;
/// RIRB Control (8-bit, RW)
pub const RIRBCTL: usize = 0x5C;
/// RIRB Status (8-bit, RW1C)
pub const RIRBSTS: usize = 0x5D;
/// RIRB Size (8-bit, RW)
pub const RIRBSIZE: usize = 0x5E;

// =============================================================================
// Immediate Command Interface (Section 4.5)
// =============================================================================

/// Immediate Command (32-bit, RW)
pub const IC: usize = 0x60;
/// Immediate Response (32-bit, RO)
pub const IR: usize = 0x64;
/// Immediate Command Status (8-bit, RW)
pub const IRS: usize = 0x68;

// =============================================================================
// Stream Descriptor Registers (Section 4.6)
// =============================================================================

/// Base offset for stream descriptors
pub const STREAM_BASE: usize = 0x80;
/// Stride between stream descriptor register sets
pub const STREAM_STRIDE: usize = 0x20;

/// Stream Descriptor Control (24-bit, RW) - offset within stream
pub const SD_CTL: usize = 0x00;
/// Stream Descriptor Status (8-bit, RW1C) - offset within stream
pub const SD_STS: usize = 0x03;
/// Stream Descriptor Link Position in Buffer (32-bit, RO)
pub const SD_LPIB: usize = 0x04;
/// Stream Descriptor Cyclic Buffer Length (32-bit, RW)
pub const SD_CBL: usize = 0x08;
/// Stream Descriptor Last Valid Index (16-bit, RW)
pub const SD_LVI: usize = 0x0C;
/// Stream Descriptor FIFO Size (16-bit, RO)
pub const SD_FIFOS: usize = 0x10;
/// Stream Descriptor Format (16-bit, RW)
pub const SD_FMT: usize = 0x12;
/// Stream Descriptor BDL Pointer Lower (32-bit, RW)
pub const SD_BDPL: usize = 0x18;
/// Stream Descriptor BDL Pointer Upper (32-bit, RW)
pub const SD_BDPU: usize = 0x1C;

// =============================================================================
// GCTL Bits (Section 4.2.2)
// =============================================================================

/// Controller Reset bit
pub const GCTL_CRST: u32 = 1 << 0;
/// Flush Control bit
pub const GCTL_FCNTRL: u32 = 1 << 1;
/// Accept Unsolicited Response Enable
pub const GCTL_UNSOL: u32 = 1 << 8;

// =============================================================================
// CORBCTL Bits (Section 4.3.5)
// =============================================================================

/// CORB DMA Engine Run
pub const CORBCTL_CORBRUN: u8 = 1 << 1;
/// CORB Memory Error Interrupt Enable
pub const CORBCTL_CMEIE: u8 = 1 << 0;

// =============================================================================
// CORBSTS Bits (Section 4.3.6)
// =============================================================================

/// CORB Memory Error Indication
pub const CORBSTS_CMEI: u8 = 1 << 0;

// =============================================================================
// RIRBCTL Bits (Section 4.4.5)
// =============================================================================

/// RIRB DMA Enable
pub const RIRBCTL_RIRBDMAEN: u8 = 1 << 1;
/// Response Interrupt Control
pub const RIRBCTL_RINTCTL: u8 = 1 << 0;
/// Response Overrun Interrupt Control
pub const RIRBCTL_RIRBOIC: u8 = 1 << 2;

// =============================================================================
// RIRBSTS Bits (Section 4.4.6)
// =============================================================================

/// Response Overrun Interrupt Status
pub const RIRBSTS_RIRBOIS: u8 = 1 << 2;
/// Response Interrupt
pub const RIRBSTS_RINTFL: u8 = 1 << 0;

// =============================================================================
// IRS Bits (Section 4.5.3)
// =============================================================================

/// Immediate Command Busy
pub const IRS_BUSY: u8 = 1 << 0;
/// Immediate Result Valid
pub const IRS_VALID: u8 = 1 << 1;

// =============================================================================
// Stream Descriptor CTL Bits (Section 4.6.1)
// =============================================================================

/// Stream Reset
pub const SD_CTL_SRST: u32 = 1 << 0;
/// Stream Run
pub const SD_CTL_RUN: u32 = 1 << 1;
/// Interrupt on Completion Enable
pub const SD_CTL_IOCE: u32 = 1 << 2;
/// FIFO Error Interrupt Enable
pub const SD_CTL_FEIE: u32 = 1 << 3;
/// Descriptor Error Interrupt Enable
pub const SD_CTL_DEIE: u32 = 1 << 4;

// =============================================================================
// Stream Descriptor STS Bits (Section 4.6.2)
// =============================================================================

/// Buffer Completion Interrupt Status
pub const SD_STS_BCIS: u8 = 1 << 2;
/// FIFO Error
pub const SD_STS_FIFOE: u8 = 1 << 3;
/// Descriptor Error
pub const SD_STS_DESE: u8 = 1 << 4;
/// FIFO Ready
pub const SD_STS_FIFORDY: u8 = 1 << 5;

// =============================================================================
// Codec Verbs (Section 7)
// =============================================================================

/// Get Parameter verb
pub const VERB_GET_PARAMETER: u16 = 0xF00;
/// Set Converter Format verb
pub const VERB_SET_CONVERTER_FORMAT: u16 = 0x200;
/// Set Converter Channel/Stream verb
pub const VERB_SET_CONV_CHANNEL_COUNT: u16 = 0x70D;
/// Set Power State verb
pub const VERB_SET_POWER_STATE: u16 = 0x705;
/// Set Pin Widget Control verb
pub const VERB_SET_PIN_WIDGET_CONTROL: u16 = 0x707;
/// Set EAPD/BTL Enable verb
pub const VERB_SET_EAPD_BTL_ENABLE: u16 = 0x70C;
/// Set Connection Select verb
pub const VERB_SET_CONNECTION_SELECT: u16 = 0x701;
/// Get Connection List Entry verb
pub const VERB_GET_CONNECTION_LIST_ENTRY: u16 = 0xF02;
/// Set Amp Gain/Mute verb
pub const VERB_SET_AMP_GAIN_MUTE: u16 = 0x300;

// =============================================================================
// Parameter IDs (Section 7.3.4)
// =============================================================================

/// Vendor ID parameter
pub const PARAM_VENDOR_ID: u16 = 0x00;
/// Revision ID parameter
pub const PARAM_REVISION_ID: u16 = 0x02;
/// Subordinate Node Count parameter
pub const PARAM_SUB_NODE_COUNT: u16 = 0x04;
/// Function Group Type parameter
pub const PARAM_FN_GROUP_TYPE: u16 = 0x05;
/// Audio Widget Capabilities parameter
pub const PARAM_AUDIO_WIDGET_CAP: u16 = 0x09;
/// Pin Capabilities parameter
pub const PARAM_PIN_CAP: u16 = 0x0C;
/// Connection List Length parameter
pub const PARAM_CONN_LIST_LEN: u16 = 0x0E;

// =============================================================================
// Timing Constants
// =============================================================================

/// Default spin timeout (microseconds equivalent in spin iterations)
pub const SPIN_TIMEOUT_DEFAULT: u32 = 1_000_000;
/// Short spin timeout for quick operations
pub const SPIN_TIMEOUT_SHORT: u32 = 100_000;
/// Long spin timeout for playback operations
pub const SPIN_TIMEOUT_LONG: u32 = 10_000_000;

// =============================================================================
// Buffer Sizes
// =============================================================================

/// Number of entries in CORB (256 entries)
pub const CORB_ENTRIES: usize = 256;
/// Number of entries in RIRB (256 entries)
pub const RIRB_ENTRIES: usize = 256;
/// Size of CORB in bytes (4 bytes per entry)
pub const CORB_SIZE: usize = CORB_ENTRIES * 4;
/// Size of RIRB in bytes (8 bytes per response)
pub const RIRB_SIZE: usize = RIRB_ENTRIES * 8;
/// Number of BDL entries per stream
pub const BDL_ENTRIES: usize = 16;
/// Default PCM buffer size (64 KiB)
pub const PCM_BUFFER_SIZE: usize = 64 * 1024;
/// DMA alignment requirement
pub const DMA_ALIGNMENT: usize = 128;

// =============================================================================
// Default Audio Format
// =============================================================================

/// Default sample rate (48 kHz)
pub const DEFAULT_SAMPLE_RATE: u32 = 48_000;
/// Default bits per sample
pub const DEFAULT_BITS_PER_SAMPLE: u16 = 16;
/// Default channel count
pub const DEFAULT_CHANNELS: u16 = 2;
