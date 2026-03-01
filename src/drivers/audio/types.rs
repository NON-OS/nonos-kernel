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

//! HD Audio data types and structures.

use core::fmt;
use core::ptr;
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};

use super::constants::{
    DMA_ALIGNMENT, DEFAULT_SAMPLE_RATE, DEFAULT_BITS_PER_SAMPLE, DEFAULT_CHANNELS,
    MAX_CHANNELS, MIN_BITS_PER_SAMPLE, MAX_BITS_PER_SAMPLE, SD_FMT_BASE_44K,
    SAMPLE_RATE_44K,
};
use super::error::AudioError;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BdlEntry {
    pub addr_lo: u32,
    pub addr_hi: u32,
    pub length: u32,
    pub flags: u32,
}

impl BdlEntry {
    pub const IOC_FLAG: u32 = 1 << 0;

    #[inline]
    pub const fn new(phys_addr: u64, length: u32, ioc: bool) -> Self {
        debug_assert!(phys_addr % DMA_ALIGNMENT as u64 == 0, "BDL address must be 128-byte aligned");

        Self {
            addr_lo: (phys_addr & 0xFFFF_FFFF) as u32,
            addr_hi: (phys_addr >> 32) as u32,
            length,
            flags: if ioc { Self::IOC_FLAG } else { 0 },
        }
    }

    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            addr_lo: 0,
            addr_hi: 0,
            length: 0,
            flags: 0,
        }
    }

    #[inline]
    pub const fn phys_addr(&self) -> u64 {
        ((self.addr_hi as u64) << 32) | (self.addr_lo as u64)
    }

    #[inline]
    pub const fn has_ioc(&self) -> bool {
        (self.flags & Self::IOC_FLAG) != 0
    }

    #[inline]
    pub const fn len(&self) -> u32 {
        self.length
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    #[inline]
    pub const fn is_valid(&self) -> bool {
        self.length > 0 && (self.phys_addr() % DMA_ALIGNMENT as u64 == 0)
    }
}

impl fmt::Debug for BdlEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let addr_lo = { self.addr_lo };
        let addr_hi = { self.addr_hi };
        let length = { self.length };
        let flags = { self.flags };

        f.debug_struct("BdlEntry")
            .field("phys_addr", &format_args!("{:#018X}", ((addr_hi as u64) << 32) | addr_lo as u64))
            .field("length", &length)
            .field("ioc", &(flags & Self::IOC_FLAG != 0))
            .finish()
    }
}

const _: () = assert!(core::mem::size_of::<BdlEntry>() == 16);

pub struct DmaRegion {
    pub va: VirtAddr,
    pub pa: PhysAddr,
    pub size: usize,
}

// SAFETY: DmaRegion contains VirtAddr/PhysAddr which are wrapped u64s, access synchronized via Mutex
unsafe impl Send for DmaRegion {}
unsafe impl Sync for DmaRegion {}

impl DmaRegion {
    pub fn new(size: usize) -> Result<Self, AudioError> {
        if size == 0 {
            return Err(AudioError::InvalidParameter);
        }

        let constraints = DmaConstraints {
            alignment: DMA_ALIGNMENT,
            max_segment_size: size,
            dma32_only: false,
            coherent: true,
        };

        let dma_region = alloc_dma_coherent(size, constraints)
            .map_err(|_| AudioError::DmaAllocationFailed)?;

        let (va, pa) = (dma_region.virt_addr, dma_region.phys_addr);

        // SAFETY: va is valid pointer to `size` bytes of DMA memory we just allocated
        unsafe {
            ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, size);
        }

        Ok(Self { va, pa, size })
    }

    #[inline]
    pub fn as_mut_ptr<T>(&self) -> *mut T {
        self.va.as_mut_ptr::<T>()
    }

    #[inline]
    pub fn as_ptr<T>(&self) -> *const T {
        self.va.as_ptr::<T>()
    }

    #[inline]
    pub fn phys(&self) -> u64 {
        self.pa.as_u64()
    }

    #[inline]
    pub fn virt(&self) -> VirtAddr {
        self.va
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.size
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    #[inline]
    pub fn in_bounds(&self, offset: usize) -> bool {
        offset < self.size
    }

    #[inline]
    pub fn validate_range(&self, offset: usize, len: usize) -> bool {
        offset.checked_add(len).map_or(false, |end| end <= self.size)
    }

    pub unsafe fn zero(&self) { unsafe {
        // SAFETY: caller ensures no concurrent access
        ptr::write_bytes(self.va.as_mut_ptr::<u8>(), 0, self.size);
    }}
}

impl fmt::Debug for DmaRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DmaRegion")
            .field("va", &format_args!("{:#X}", self.va.as_u64()))
            .field("pa", &format_args!("{:#X}", self.pa.as_u64()))
            .field("size", &self.size)
            .finish()
    }
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct AudioStats {
    pub samples_played: u64,
    pub samples_recorded: u64,
    pub buffer_underruns: u64,
    pub buffer_overruns: u64,
    pub interrupts_handled: u64,
    pub active_streams: u64,
    pub codecs_detected: u32,
    pub bytes_transferred: u64,
    pub error_count: u64,
}

impl AudioStats {
    pub const fn new() -> Self {
        Self {
            samples_played: 0,
            samples_recorded: 0,
            buffer_underruns: 0,
            buffer_overruns: 0,
            interrupts_handled: 0,
            active_streams: 0,
            codecs_detected: 0,
            bytes_transferred: 0,
            error_count: 0,
        }
    }

    pub const fn has_errors(&self) -> bool {
        self.buffer_underruns > 0 || self.buffer_overruns > 0 || self.error_count > 0
    }

    pub const fn total_errors(&self) -> u64 {
        self.buffer_underruns + self.buffer_overruns + self.error_count
    }
}

impl fmt::Display for AudioStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AudioStats {{ samples: {}, codecs: {}, streams: {}, errors: {} }}",
            self.samples_played,
            self.codecs_detected,
            self.active_streams,
            self.total_errors()
        )
    }
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StreamState {
    Stopped = 0,
    Running = 1,
    Paused = 2,
    Error = 3,
    Resetting = 4,
    Ready = 5,
}

impl StreamState {
    #[inline]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Running)
    }

    #[inline]
    pub const fn can_start(&self) -> bool {
        matches!(self, Self::Stopped | Self::Ready | Self::Paused)
    }

    #[inline]
    pub const fn can_stop(&self) -> bool {
        matches!(self, Self::Running | Self::Paused | Self::Error)
    }

    #[inline]
    pub const fn is_error(&self) -> bool {
        matches!(self, Self::Error)
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Error => "error",
            Self::Resetting => "resetting",
            Self::Ready => "ready",
        }
    }
}

impl Default for StreamState {
    fn default() -> Self {
        Self::Stopped
    }
}

impl fmt::Display for StreamState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Volume(u8);

impl Volume {
    pub const MIN: Self = Self(0);
    pub const MAX: Self = Self(100);
    pub const DEFAULT: Self = Self(80);

    #[inline]
    pub const fn new(percent: u8) -> Self {
        if percent > 100 {
            Self(100)
        } else {
            Self(percent)
        }
    }

    #[inline]
    pub const fn percent(&self) -> u8 {
        self.0
    }

    #[inline]
    pub const fn to_gain(&self) -> u8 {
        ((self.0 as u16 * 127) / 100) as u8
    }

    #[inline]
    pub const fn from_gain(gain: u8) -> Self {
        let percent = ((gain as u16 * 100) / 127) as u8;
        Self::new(percent)
    }

    #[inline]
    pub const fn is_muted(&self) -> bool {
        self.0 == 0
    }
}

impl Default for Volume {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for Volume {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}%", self.0)
    }
}

#[cfg(test)]
mod tests {
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
}
