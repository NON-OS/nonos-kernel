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
//! HD Audio driver error types.

use core::fmt;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioError {
    /// PCI BAR0 is not an MMIO region
    Bar0NotMmio,
    /// Failed to clear controller reset (CRST)
    CrstClearTimeout,
    /// Failed to set controller reset (CRST)
    CrstSetTimeout,
    /// DMA allocation failed
    DmaAllocationFailed,
    /// No HD Audio controller found on PCI bus
    NoControllerFound,
    /// No codec detected on the HDA link
    NoCodecPresent,
    /// Immediate command interface busy timeout
    ImmediateCmdBusy,
    /// Immediate command response timeout
    ImmediateResponseTimeout,
    /// CORB/RIRB command timed out
    CorbRirbTimeout,
    /// Stream reset set timeout
    StreamResetSetTimeout,
    /// Stream reset clear timeout
    StreamResetClearTimeout,
    /// Unsupported PCM format requested
    UnsupportedFormat,
    /// Playback did not complete in time
    PlaybackTimeout,
    /// Controller not initialized
    NotInitialized,
    /// Stream not configured
    StreamNotConfigured,
    /// Invalid stream index
    InvalidStreamIndex,
    /// Buffer too large for single BDL entry
    BufferTooLarge,
    /// Codec initialization failed
    CodecInitFailed,
}
/// Returns a human-readable description of the error.
impl AudioError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Bar0NotMmio => "HDA BAR0 is not MMIO",
            Self::CrstClearTimeout => "Failed to clear controller reset",
            Self::CrstSetTimeout => "Failed to set controller reset",
            Self::DmaAllocationFailed => "DMA allocation failed",
            Self::NoControllerFound => "No HD Audio controller found",
            Self::NoCodecPresent => "No codec present on HDA link",
            Self::ImmediateCmdBusy => "Immediate command busy timeout",
            Self::ImmediateResponseTimeout => "Immediate response timeout",
            Self::CorbRirbTimeout => "CORB/RIRB command timeout",
            Self::StreamResetSetTimeout => "Stream reset set timeout",
            Self::StreamResetClearTimeout => "Stream reset clear timeout",
            Self::UnsupportedFormat => "Unsupported PCM format",
            Self::PlaybackTimeout => "Playback did not complete in time",
            Self::NotInitialized => "Controller not initialized",
            Self::StreamNotConfigured => "Stream not configured",
            Self::InvalidStreamIndex => "Invalid stream index",
            Self::BufferTooLarge => "Buffer too large for BDL entry",
            Self::CodecInitFailed => "Codec initialization failed",
        }
    }
}

impl fmt::Display for AudioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// Allow conversion from &'static str for backward compatibility
impl From<&'static str> for AudioError {
    fn from(s: &'static str) -> Self {
        match s {
            "HDA BAR0 is not MMIO" => Self::Bar0NotMmio,
            "HDA: failed to clear CRST" => Self::CrstClearTimeout,
            "HDA: failed to set CRST" => Self::CrstSetTimeout,
            "No HD Audio controller found" => Self::NoControllerFound,
            "HDA: no codec present" => Self::NoCodecPresent,
            "HDA: immediate command busy timeout" => Self::ImmediateCmdBusy,
            "HDA: immediate response timeout" => Self::ImmediateResponseTimeout,
            "HDA: stream SRST set timeout" => Self::StreamResetSetTimeout,
            "HDA: stream SRST clear timeout" => Self::StreamResetClearTimeout,
            "Unsupported PCM format requested" => Self::UnsupportedFormat,
            "HDA: playback did not complete in time" => Self::PlaybackTimeout,
            _ => Self::NotInitialized, // Default fallback
        }
    }
}
