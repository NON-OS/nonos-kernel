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
//! HD Audio data types and structures.

use core::ptr;
use x86_64::{PhysAddr, VirtAddr};
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};
use super::constants::DMA_ALIGNMENT;
use super::error::AudioError;

// =============================================================================
// Buffer Descriptor List Entry (Section 4.6.4)
// =============================================================================

/// Buffer Descriptor List Entry.
///
/// Each BDL entry describes one buffer fragment in the scatter-gather list.
/// The controller uses these entries to locate PCM data in memory.
///
/// # Layout (per HDA spec)
///
/// - Bytes 0-3: Buffer address (low 32 bits)
/// - Bytes 4-7: Buffer address (high 32 bits)
/// - Bytes 8-11: Buffer length in bytes
/// - Bytes 12-15: Flags (bit 0 = IOC - Interrupt on Completion)

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BdlEntry {
    /// Lower 32 bits of buffer physical address
    pub addr_lo: u32,
    /// Upper 32 bits of buffer physical address
    pub addr_hi: u32,
    /// Length of buffer in bytes
    pub length: u32,
    /// Flags: bit 0 = IOC (Interrupt on Completion)
    pub flags: u32,
}

impl BdlEntry {
    #[inline]
    pub const fn new(phys_addr: u64, length: u32, ioc: bool) -> Self {
        Self {
            addr_lo: (phys_addr & 0xFFFF_FFFF) as u32,
            addr_hi: (phys_addr >> 32) as u32,
            length,
            flags: if ioc { 1 } else { 0 },
        }
    }

    /// Creates an empty/zeroed BDL entry.
    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            addr_lo: 0,
            addr_hi: 0,
            length: 0,
            flags: 0,
        }
    }

    /// Returns the physical address from this entry.
    #[inline]
    pub const fn phys_addr(&self) -> u64 {
        ((self.addr_hi as u64) << 32) | (self.addr_lo as u64)
    }
}

// Verify BDL entry is exactly 16 bytes as required by spec
const _: () = assert!(core::mem::size_of::<BdlEntry>() == 16);

// =============================================================================
// DMA Region
// =============================================================================

/// Wrapper for raw pointer that implements Send.
///
/// # Safety
///
/// This is safe because the underlying memory is DMA-coherent memory
/// that is never deallocated during the controller's lifetime, and
/// all access is synchronized through the controller's Mutex.
pub(crate) struct SendPtr<T>(pub *mut T);

// SAFETY: The pointer points to DMA-coherent memory that persists for
// the lifetime of the controller. All access is synchronized via Mutex.
unsafe impl<T> Send for SendPtr<T> {}
unsafe impl<T> Sync for SendPtr<T> {}

/// DMA-coherent memory region for HD Audio operations.
///
/// Manages a contiguous block of DMA-coherent memory that can be safely
/// accessed by both the CPU and the HD Audio controller's DMA engine.
///
/// # Memory Safety
///
/// The region is allocated from the DMA-coherent pool and zeroed on creation.
/// The memory persists for the lifetime of the controller.
pub struct DmaRegion {
    /// Virtual address for CPU access
    pub va: VirtAddr,
    /// Physical address for DMA engine
    pub pa: PhysAddr,
    /// Size of the region in bytes
    pub size: usize,
}

impl DmaRegion {
    /// Allocates a new DMA-coherent region.
    ///
    /// # Memory Layout
    ///
    /// The region is allocated with 128-byte alignment (required by HDA spec)
    /// and zeroed before returning.
    pub fn new(size: usize) -> Result<Self, AudioError> {
        let constraints = DmaConstraints {
            alignment: DMA_ALIGNMENT,
            max_segment_size: size,
            dma32_only: false,
            coherent: true,
        };

        let dma_region = alloc_dma_coherent(size, constraints)
            .map_err(|_| AudioError::DmaAllocationFailed)?;

        let (va, pa) = (dma_region.virt_addr, dma_region.phys_addr);

        // SAFETY: va is a valid pointer to `size` bytes of DMA memory
        // that we just allocated. Zeroing ensures clean initial state.
        unsafe {
            ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, size);
        }

        Ok(Self { va, pa, size })
    }

    /// Returns a mutable pointer to the region's data.
    ///
    /// # Safety
    ///
    /// Caller must ensure proper synchronization when accessing the memory.
    #[inline]
    pub fn as_mut_ptr<T>(&self) -> *mut T {
        self.va.as_mut_ptr::<T>()
    }

    /// Returns a const pointer to the region's data.
    #[inline]
    pub fn as_ptr<T>(&self) -> *const T {
        self.va.as_ptr::<T>()
    }

    /// Returns the physical address of the region.
    #[inline]
    pub fn phys(&self) -> u64 {
        self.pa.as_u64()
    }

    /// Returns the size of the region in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.size
    }

    /// Returns true if the region is empty (size == 0).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

// =============================================================================
// Audio Statistics
// =============================================================================

#[derive(Default, Clone, Copy, Debug)]
pub struct AudioStats {
    /// Number of samples played (approximate, based on bytes)
    pub samples_played: u64,
    /// Number of samples recorded (for future input support)
    pub samples_recorded: u64,
    /// Number of buffer underrun events
    pub buffer_underruns: u64,
    /// Number of buffer overrun events
    pub buffer_overruns: u64,
    /// Number of interrupts handled
    pub interrupts_handled: u64,
    /// Number of currently active streams
    pub active_streams: u64,
    /// Number of codecs detected on the HDA link
    pub codecs_detected: u32,
}

impl AudioStats {
    /// Creates a new statistics instance with all counters at zero.
    pub const fn new() -> Self {
        Self {
            samples_played: 0,
            samples_recorded: 0,
            buffer_underruns: 0,
            buffer_overruns: 0,
            interrupts_handled: 0,
            active_streams: 0,
            codecs_detected: 0,
        }
    }
}

// =============================================================================
// Audio Format
// =============================================================================

/// PCM audio format configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AudioFormat {
    /// Sample rate in Hz (e.g., 44100, 48000)
    pub sample_rate: u32,
    /// Bits per sample (e.g., 16, 24, 32)
    pub bits_per_sample: u16,
    /// Number of channels (e.g., 2 for stereo)
    pub channels: u16,
}

impl AudioFormat {
    /// Creates a new audio format.
    pub const fn new(sample_rate: u32, bits_per_sample: u16, channels: u16) -> Self {
        Self {
            sample_rate,
            bits_per_sample,
            channels,
        }
    }

    /// Returns the default format: 48 kHz, 16-bit, stereo.
    pub const fn default_format() -> Self {
        Self {
            sample_rate: 48_000,
            bits_per_sample: 16,
            channels: 2,
        }
    }

    /// Calculates bytes per sample (all channels).
    #[inline]
    pub const fn bytes_per_sample(&self) -> usize {
        (self.bits_per_sample as usize / 8) * self.channels as usize
    }

    /// Calculates bytes per second at this format.
    #[inline]
    pub const fn bytes_per_second(&self) -> usize {
        self.bytes_per_sample() * self.sample_rate as usize
    }

    /// Encodes format as HDA stream format register value.
    ///
    /// # Format Register Layout (Section 4.6.8)
    ///
    /// - Bits 15:14: Sample Base Rate Multiplier
    /// - Bits 13:11: Sample Base Rate (0=48kHz, 1=44.1kHz)
    /// - Bits 10:8: Sample Base Rate Divisor
    /// - Bits 7:4: Bits per Sample (0000=8, 0001=16, 0010=20, 0011=24, 0100=32)
    /// - Bits 3:0: Number of Channels minus 1
    ///
    /// # Returns
    ///
    /// `Some(format_value)` if the format is supported, `None` otherwise.
    pub fn to_hda_format(&self) -> Option<u16> {
        // Currently only support 48 kHz, 16-bit, 2-channel
        if self.sample_rate != 48_000 || self.bits_per_sample != 16 || self.channels != 2 {
            return None;
        }

        // Base rate = 48kHz (001), rate divisor = 1x (000), bits = 16 (0001), channels-1 = 1 (0001)
        let base = 0b001 << 11;
        let rate_bits = 0b000 << 8;
        let bits_bits = 0b0001 << 4;
        let chans_bits = (self.channels - 1) as u16;

        Some(base | rate_bits | bits_bits | chans_bits)
    }
}

impl Default for AudioFormat {
    fn default() -> Self {
        Self::default_format()
    }
}

// =============================================================================
// Stream State
// =============================================================================

/// State of an audio stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is stopped
    Stopped,
    /// Stream is running
    Running,
    /// Stream is paused
    Paused,
    /// Stream encountered an error
    Error,
}

impl Default for StreamState {
    fn default() -> Self {
        Self::Stopped
    }
}
