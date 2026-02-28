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

use core::sync::atomic::{AtomicBool, AtomicU64};
use super::{ports, command};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PitError {
    NotInitialized = 0,
    AlreadyInitialized = 1,
    InvalidFrequency = 2,
    InvalidDivisor = 3,
    InvalidChannel = 4,
    InvalidMode = 5,
    ChannelBusy = 6,
    Timeout = 7,
    HardwareError = 8,
    CalibrationFailed = 9,
    SpeakerUnavailable = 10,
    OneShotPending = 11,
}

impl PitError {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotInitialized => "PIT not initialized",
            Self::AlreadyInitialized => "PIT already initialized",
            Self::InvalidFrequency => "Invalid frequency requested",
            Self::InvalidDivisor => "Invalid divisor value",
            Self::InvalidChannel => "Invalid channel specified",
            Self::InvalidMode => "Invalid operating mode",
            Self::ChannelBusy => "Channel not available",
            Self::Timeout => "Timeout waiting for operation",
            Self::HardwareError => "Hardware access error",
            Self::CalibrationFailed => "Calibration failed",
            Self::SpeakerUnavailable => "Speaker not available",
            Self::OneShotPending => "One-shot timer already pending",
        }
    }
}

pub type PitResult<T> = Result<T, PitError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Channel {
    Channel0 = 0,
    Channel1 = 1,
    Channel2 = 2,
}

impl Channel {
    pub const fn data_port(&self) -> u16 {
        match self {
            Self::Channel0 => ports::CHANNEL0,
            Self::Channel1 => ports::CHANNEL1,
            Self::Channel2 => ports::CHANNEL2,
        }
    }

    pub const fn select_bits(&self) -> u8 {
        match self {
            Self::Channel0 => command::CHANNEL_0,
            Self::Channel1 => command::CHANNEL_1,
            Self::Channel2 => command::CHANNEL_2,
        }
    }

    pub const fn readback_bit(&self) -> u8 {
        match self {
            Self::Channel0 => command::READBACK_CH0,
            Self::Channel1 => command::READBACK_CH1,
            Self::Channel2 => command::READBACK_CH2,
        }
    }

    pub const fn from_num(num: u8) -> Option<Self> {
        match num {
            0 => Some(Self::Channel0),
            1 => Some(Self::Channel1),
            2 => Some(Self::Channel2),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Mode {
    InterruptOnTerminal = 0,
    HardwareOneShot = 1,
    #[default]
    RateGenerator = 2,
    SquareWave = 3,
    SoftwareStrobe = 4,
    HardwareStrobe = 5,
}

impl Mode {
    pub const fn bits(&self) -> u8 {
        match self {
            Self::InterruptOnTerminal => command::MODE_0,
            Self::HardwareOneShot => command::MODE_1,
            Self::RateGenerator => command::MODE_2,
            Self::SquareWave => command::MODE_3,
            Self::SoftwareStrobe => command::MODE_4,
            Self::HardwareStrobe => command::MODE_5,
        }
    }

    pub const fn from_num(num: u8) -> Option<Self> {
        match num {
            0 => Some(Self::InterruptOnTerminal),
            1 => Some(Self::HardwareOneShot),
            2 => Some(Self::RateGenerator),
            3 => Some(Self::SquareWave),
            4 => Some(Self::SoftwareStrobe),
            5 => Some(Self::HardwareStrobe),
            _ => None,
        }
    }

    pub const fn is_periodic(&self) -> bool {
        matches!(self, Self::RateGenerator | Self::SquareWave)
    }

    pub const fn is_oneshot(&self) -> bool {
        matches!(
            self,
            Self::InterruptOnTerminal | Self::HardwareOneShot |
            Self::SoftwareStrobe | Self::HardwareStrobe
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AccessMode {
    Latch = 0,
    LowByte = 1,
    HighByte = 2,
    LowHigh = 3,
}

impl AccessMode {
    pub const fn bits(&self) -> u8 {
        match self {
            Self::Latch => command::ACCESS_LATCH,
            Self::LowByte => command::ACCESS_LOBYTE,
            Self::HighByte => command::ACCESS_HIBYTE,
            Self::LowHigh => command::ACCESS_LOHI,
        }
    }
}

#[derive(Debug)]
pub(super) struct ChannelState {
    pub(super) configured: bool,
    pub(super) mode: Mode,
    pub(super) divisor: u16,
    pub(super) frequency_hz: u32,
    pub(super) tick_count: AtomicU64,
    pub(super) oneshot_pending: AtomicBool,
}

impl Default for ChannelState {
    fn default() -> Self {
        Self {
            configured: false,
            mode: Mode::RateGenerator,
            divisor: 0,
            frequency_hz: 0,
            tick_count: AtomicU64::new(0),
            oneshot_pending: AtomicBool::new(false),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PitStatistics {
    pub initialized: bool,
    pub channel0_frequency: u32,
    pub channel0_divisor: u16,
    pub channel0_ticks: u64,
    pub channel2_frequency: u32,
    pub channel2_divisor: u16,
    pub calibrations: u64,
    pub last_calibration_hz: u64,
    pub speaker_beeps: u64,
    pub oneshot_completed: u64,
}
