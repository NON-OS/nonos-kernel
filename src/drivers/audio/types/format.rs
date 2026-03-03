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

use super::super::constants::{
    DEFAULT_SAMPLE_RATE, DEFAULT_BITS_PER_SAMPLE, DEFAULT_CHANNELS,
    MAX_CHANNELS, MIN_BITS_PER_SAMPLE, MAX_BITS_PER_SAMPLE, SD_FMT_BASE_44K,
    SAMPLE_RATE_44K,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AudioFormat {
    pub sample_rate: u32,
    pub bits_per_sample: u16,
    pub channels: u16,
}

impl AudioFormat {
    pub const fn new(sample_rate: u32, bits_per_sample: u16, channels: u16) -> Self {
        Self {
            sample_rate,
            bits_per_sample,
            channels,
        }
    }

    pub const fn default_format() -> Self {
        Self {
            sample_rate: DEFAULT_SAMPLE_RATE,
            bits_per_sample: DEFAULT_BITS_PER_SAMPLE,
            channels: DEFAULT_CHANNELS,
        }
    }

    pub const fn cd_quality() -> Self {
        Self {
            sample_rate: SAMPLE_RATE_44K,
            bits_per_sample: 16,
            channels: 2,
        }
    }

    pub const fn mono(sample_rate: u32) -> Self {
        Self {
            sample_rate,
            bits_per_sample: 16,
            channels: 1,
        }
    }

    pub const fn is_valid(&self) -> bool {
        self.sample_rate > 0
            && self.bits_per_sample >= MIN_BITS_PER_SAMPLE
            && self.bits_per_sample <= MAX_BITS_PER_SAMPLE
            && self.channels >= 1
            && self.channels <= MAX_CHANNELS
    }

    pub const fn is_supported(&self) -> bool {
        (self.sample_rate == DEFAULT_SAMPLE_RATE || self.sample_rate == SAMPLE_RATE_44K)
            && self.bits_per_sample == 16
            && self.channels >= 1
            && self.channels <= MAX_CHANNELS
    }

    #[inline]
    pub const fn bytes_per_sample(&self) -> usize {
        (self.bits_per_sample as usize / 8) * self.channels as usize
    }

    #[inline]
    pub const fn bytes_per_second(&self) -> usize {
        self.bytes_per_sample() * self.sample_rate as usize
    }

    #[inline]
    pub const fn bytes_to_ms(&self, bytes: usize) -> u64 {
        let bps = self.bytes_per_second();
        if bps == 0 {
            return 0;
        }
        (bytes as u64 * 1000) / bps as u64
    }

    #[inline]
    pub const fn ms_to_bytes(&self, ms: u64) -> usize {
        (self.bytes_per_second() as u64 * ms / 1000) as usize
    }

    fn calculate_mult_div(&self) -> Option<(u32, u32)> {
        let base = if self.sample_rate % SAMPLE_RATE_44K == 0 ||
                      (SAMPLE_RATE_44K * 2) % self.sample_rate == 0 {
            SAMPLE_RATE_44K
        } else {
            DEFAULT_SAMPLE_RATE
        };

        if self.sample_rate == base {
            return Some((1, 1));
        }

        for mult in 1u32..=4 {
            for div in 1u32..=8 {
                if base * mult / div == self.sample_rate {
                    return Some((mult, div));
                }
            }
        }

        if self.sample_rate == base {
            Some((1, 1))
        } else {
            None
        }
    }

    pub fn to_hda_format(&self) -> Option<u16> {
        if !self.is_supported() {
            return None;
        }

        let base = if self.sample_rate == SAMPLE_RATE_44K {
            SD_FMT_BASE_44K
        } else {
            0
        };

        let (mult, div) = self.calculate_mult_div()?;
        let mult_enc = (mult - 1) as u16;
        let div_enc = (div - 1) as u16;

        let bits = match self.bits_per_sample {
            8 => 0b000,
            16 => 0b001,
            20 => 0b010,
            24 => 0b011,
            32 => 0b100,
            _ => return None,
        };

        let chans = (self.channels - 1) as u16;

        Some(base | (mult_enc << 11) | (div_enc << 8) | (bits << 4) | chans)
    }

    pub fn from_hda_format(value: u16) -> Option<Self> {
        if value & (1 << 15) != 0 {
            return None;
        }

        let base = if value & SD_FMT_BASE_44K != 0 { SAMPLE_RATE_44K } else { DEFAULT_SAMPLE_RATE };
        let mult = ((value >> 11) & 0x7) + 1;
        let div = ((value >> 8) & 0x7) + 1;
        let sample_rate = (base as u32 * mult as u32) / div as u32;

        let bits_enc = (value >> 4) & 0x7;
        let bits_per_sample = match bits_enc {
            0b000 => 8,
            0b001 => 16,
            0b010 => 20,
            0b011 => 24,
            0b100 => 32,
            _ => return None,
        };

        let channels = (value & 0xF) + 1;

        Some(Self {
            sample_rate,
            bits_per_sample,
            channels,
        })
    }
}

impl Default for AudioFormat {
    fn default() -> Self {
        Self::default_format()
    }
}

impl fmt::Display for AudioFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}Hz {}-bit {}ch",
            self.sample_rate, self.bits_per_sample, self.channels
        )
    }
}
