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


use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioError {
    Bar0NotMmio,
    NoControllerFound,
    NoCodecPresent,
    CrstClearTimeout,
    CrstSetTimeout,
    DmaAllocationFailed,
    NotInitialized,
    CodecInitFailed,
    ImmediateCmdBusy,
    ImmediateResponseTimeout,
    CorbRirbTimeout,
    CorbMemoryError,
    RirbOverrun,
    StreamResetSetTimeout,
    StreamResetClearTimeout,
    StreamNotConfigured,
    InvalidStreamIndex,
    PlaybackTimeout,
    BufferTooLarge,
    StreamFifoError,
    StreamDescriptorError,
    UnsupportedFormat,
    InvalidParameter,
    InvalidCodecAddress,
    InvalidNodeId,
    NoInputDevice,
    RecordingTimeout,
}

impl AudioError {
    pub const fn code(&self) -> u16 {
        match self {
            Self::Bar0NotMmio => 0x0101,
            Self::NoControllerFound => 0x0102,
            Self::NoCodecPresent => 0x0103,
            Self::CrstClearTimeout => 0x0201,
            Self::CrstSetTimeout => 0x0202,
            Self::DmaAllocationFailed => 0x0203,
            Self::NotInitialized => 0x0204,
            Self::CodecInitFailed => 0x0205,
            Self::ImmediateCmdBusy => 0x0301,
            Self::ImmediateResponseTimeout => 0x0302,
            Self::CorbRirbTimeout => 0x0303,
            Self::CorbMemoryError => 0x0304,
            Self::RirbOverrun => 0x0305,
            Self::StreamResetSetTimeout => 0x0401,
            Self::StreamResetClearTimeout => 0x0402,
            Self::StreamNotConfigured => 0x0403,
            Self::InvalidStreamIndex => 0x0404,
            Self::PlaybackTimeout => 0x0405,
            Self::BufferTooLarge => 0x0406,
            Self::StreamFifoError => 0x0407,
            Self::StreamDescriptorError => 0x0408,
            Self::UnsupportedFormat => 0x0501,
            Self::InvalidParameter => 0x0502,
            Self::InvalidCodecAddress => 0x0503,
            Self::InvalidNodeId => 0x0504,
            Self::NoInputDevice => 0x0505,
            Self::RecordingTimeout => 0x0409,
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Bar0NotMmio => "HDA BAR0 is not MMIO",
            Self::NoControllerFound => "No HD Audio controller found",
            Self::NoCodecPresent => "No codec present on HDA link",
            Self::CrstClearTimeout => "Failed to clear controller reset",
            Self::CrstSetTimeout => "Failed to set controller reset",
            Self::DmaAllocationFailed => "DMA allocation failed",
            Self::NotInitialized => "Controller not initialized",
            Self::CodecInitFailed => "Codec initialization failed",
            Self::ImmediateCmdBusy => "Immediate command busy timeout",
            Self::ImmediateResponseTimeout => "Immediate response timeout",
            Self::CorbRirbTimeout => "CORB/RIRB command timeout",
            Self::CorbMemoryError => "CORB memory error",
            Self::RirbOverrun => "RIRB overrun occurred",
            Self::StreamResetSetTimeout => "Stream reset set timeout",
            Self::StreamResetClearTimeout => "Stream reset clear timeout",
            Self::StreamNotConfigured => "Stream not configured",
            Self::InvalidStreamIndex => "Invalid stream index",
            Self::PlaybackTimeout => "Playback did not complete in time",
            Self::BufferTooLarge => "Buffer too large for BDL entry",
            Self::StreamFifoError => "Stream FIFO error",
            Self::StreamDescriptorError => "Stream descriptor error",
            Self::UnsupportedFormat => "Unsupported PCM format",
            Self::InvalidParameter => "Invalid parameter value",
            Self::InvalidCodecAddress => "Codec address out of range (0-15)",
            Self::InvalidNodeId => "Node ID out of range (0-127)",
            Self::NoInputDevice => "No audio input device available",
            Self::RecordingTimeout => "Recording did not complete in time",
        }
    }

    pub const fn recovery_hint(&self) -> &'static str {
        match self {
            Self::Bar0NotMmio => "Check PCI device configuration",
            Self::NoControllerFound => "Verify HD Audio hardware is present and enabled in BIOS",
            Self::NoCodecPresent => "Reset controller and retry; check physical connections",
            Self::CrstClearTimeout => "Power cycle system; controller may be stuck",
            Self::CrstSetTimeout => "Power cycle system; controller may be stuck",
            Self::DmaAllocationFailed => "Free memory and retry; reduce buffer sizes",
            Self::NotInitialized => "Call init_hd_audio() before using audio functions",
            Self::CodecInitFailed => "Try alternative codec or simplified path",
            Self::ImmediateCmdBusy => "Wait and retry; previous command may still be processing",
            Self::ImmediateResponseTimeout => "Reset codec and retry",
            Self::CorbRirbTimeout => "Use immediate command fallback; reset CORB/RIRB",
            Self::CorbMemoryError => "Check DMA region alignment and mapping",
            Self::RirbOverrun => "Process responses more frequently",
            Self::StreamResetSetTimeout => "Reset controller and reinitialize",
            Self::StreamResetClearTimeout => "Reset controller and reinitialize",
            Self::StreamNotConfigured => "Configure stream BDL and format before starting",
            Self::InvalidStreamIndex => "Use stream index within controller capabilities",
            Self::PlaybackTimeout => "Check stream configuration; buffer may be too large",
            Self::BufferTooLarge => "Use smaller buffer or multiple BDL entries",
            Self::StreamFifoError => "Adjust buffer timing or reduce stream count",
            Self::StreamDescriptorError => "Check BDL configuration and memory mapping",
            Self::UnsupportedFormat => "Use 48kHz 16-bit stereo PCM format",
            Self::InvalidParameter => "Check parameter ranges in documentation",
            Self::InvalidCodecAddress => "Use codec address 0-15",
            Self::InvalidNodeId => "Use node ID 0-127",
            Self::NoInputDevice => "No microphone or line-in available; check hardware",
            Self::RecordingTimeout => "Check input stream configuration",
        }
    }

    pub const fn is_recoverable(&self) -> bool {
        match self {
            Self::Bar0NotMmio | Self::NoControllerFound => false,
            Self::NoCodecPresent => true,
            Self::CrstClearTimeout | Self::CrstSetTimeout => false,
            Self::DmaAllocationFailed => true,
            Self::NotInitialized | Self::CodecInitFailed => true,
            Self::ImmediateCmdBusy
            | Self::ImmediateResponseTimeout
            | Self::CorbRirbTimeout
            | Self::CorbMemoryError
            | Self::RirbOverrun => true,
            Self::StreamResetSetTimeout | Self::StreamResetClearTimeout => false,
            Self::StreamNotConfigured | Self::InvalidStreamIndex => true,
            Self::PlaybackTimeout | Self::BufferTooLarge => true,
            Self::StreamFifoError | Self::StreamDescriptorError => true,
            Self::UnsupportedFormat
            | Self::InvalidParameter
            | Self::InvalidCodecAddress
            | Self::InvalidNodeId
            | Self::NoInputDevice
            | Self::RecordingTimeout => true,
        }
    }

    pub const fn category(&self) -> &'static str {
        match self.code() >> 8 {
            0x01 => "Hardware",
            0x02 => "Initialization",
            0x03 => "Communication",
            0x04 => "Stream",
            0x05 => "Configuration",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for AudioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type AudioResult<T> = Result<T, AudioError>;

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
            _ => Self::NotInitialized,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes_unique() {
        let errors = [
            AudioError::Bar0NotMmio,
            AudioError::NoControllerFound,
            AudioError::NoCodecPresent,
            AudioError::CrstClearTimeout,
            AudioError::CrstSetTimeout,
            AudioError::DmaAllocationFailed,
            AudioError::NotInitialized,
            AudioError::CodecInitFailed,
            AudioError::ImmediateCmdBusy,
            AudioError::ImmediateResponseTimeout,
            AudioError::CorbRirbTimeout,
            AudioError::CorbMemoryError,
            AudioError::RirbOverrun,
            AudioError::StreamResetSetTimeout,
            AudioError::StreamResetClearTimeout,
            AudioError::StreamNotConfigured,
            AudioError::InvalidStreamIndex,
            AudioError::PlaybackTimeout,
            AudioError::BufferTooLarge,
            AudioError::StreamFifoError,
            AudioError::StreamDescriptorError,
            AudioError::UnsupportedFormat,
            AudioError::InvalidParameter,
            AudioError::InvalidCodecAddress,
            AudioError::InvalidNodeId,
        ];

        for i in 0..errors.len() {
            for j in (i + 1)..errors.len() {
                assert_ne!(
                    errors[i].code(),
                    errors[j].code(),
                    "Duplicate error code: {:?} and {:?}",
                    errors[i],
                    errors[j]
                );
            }
        }
    }

    #[test]
    fn test_error_categories() {
        assert_eq!(AudioError::Bar0NotMmio.category(), "Hardware");
        assert_eq!(AudioError::DmaAllocationFailed.category(), "Initialization");
        assert_eq!(AudioError::CorbRirbTimeout.category(), "Communication");
        assert_eq!(AudioError::PlaybackTimeout.category(), "Stream");
        assert_eq!(AudioError::UnsupportedFormat.category(), "Configuration");
    }

    #[test]
    fn test_recovery_hints_non_empty() {
        let errors = [
            AudioError::Bar0NotMmio,
            AudioError::PlaybackTimeout,
            AudioError::UnsupportedFormat,
        ];

        for err in &errors {
            assert!(!err.recovery_hint().is_empty());
        }
    }
}
