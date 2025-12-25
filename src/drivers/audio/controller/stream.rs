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
//! HD Audio stream descriptor management.

use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use super::super::error::AudioError;
use super::super::types::{BdlEntry, DmaRegion, AudioFormat, StreamState};
use super::super::constants::*;
use super::helpers::{RegisterAccess, spin_until, spin_while};

// =============================================================================
// Statistics
// =============================================================================

/// Total streams started.
static STREAMS_STARTED: AtomicU32 = AtomicU32::new(0);

/// Total streams stopped.
static STREAMS_STOPPED: AtomicU32 = AtomicU32::new(0);

/// Total stream errors.
static STREAM_ERRORS: AtomicU32 = AtomicU32::new(0);

/// Returns the number of streams started.
#[inline]
pub fn streams_started_count() -> u32 {
    STREAMS_STARTED.load(Ordering::Relaxed)
}

/// Returns the number of streams stopped.
#[inline]
pub fn streams_stopped_count() -> u32 {
    STREAMS_STOPPED.load(Ordering::Relaxed)
}

/// Returns the number of stream errors.
#[inline]
pub fn stream_error_count() -> u32 {
    STREAM_ERRORS.load(Ordering::Relaxed)
}

/// Resets stream statistics.
#[inline]
pub fn reset_stream_stats() {
    STREAMS_STARTED.store(0, Ordering::Relaxed);
    STREAMS_STOPPED.store(0, Ordering::Relaxed);
    STREAM_ERRORS.store(0, Ordering::Relaxed);
}

// =============================================================================
// Stream Reset
// =============================================================================
///
/// # Steps
/// 1. Set SRST bit to enter reset
/// 2. Wait for SRST to read back as 1 (acknowledged)
/// 3. Clear SRST bit to exit reset
/// 4. Wait for SRST to read back as 0 (complete)
pub fn reset_stream<T: RegisterAccess>(ctrl: &T, stream_index: u8) -> Result<(), AudioError> {
    debug_assert!(stream_index >= 1, "Stream index must be 1-based");

    // Clear any pending status bits first
    ctrl.write_stream_reg8(stream_index, SD_STS, 0xFF);

    // Set stream reset bit
    let mut ctl = ctrl.read_stream_reg32(stream_index, SD_CTL);
    ctl |= SD_CTL_SRST;
    ctrl.write_stream_reg32(stream_index, SD_CTL, ctl);

    // Wait for reset to be acknowledged
    if !spin_until(
        || (ctrl.read_stream_reg32(stream_index, SD_CTL) & SD_CTL_SRST) != 0,
        SPIN_TIMEOUT_SHORT,
    ) {
        STREAM_ERRORS.fetch_add(1, Ordering::Relaxed);
        return Err(AudioError::StreamResetSetTimeout);
    }

    // Clear stream reset bit
    let mut ctl = ctrl.read_stream_reg32(stream_index, SD_CTL);
    ctl &= !SD_CTL_SRST;
    ctrl.write_stream_reg32(stream_index, SD_CTL, ctl);

    // Wait for reset to complete
    if !spin_while(
        || (ctrl.read_stream_reg32(stream_index, SD_CTL) & SD_CTL_SRST) != 0,
        SPIN_TIMEOUT_SHORT,
    ) {
        STREAM_ERRORS.fetch_add(1, Ordering::Relaxed);
        return Err(AudioError::StreamResetClearTimeout);
    }

    Ok(())
}

// =============================================================================
// BDL Configuration
// =============================================================================
/// Debug builds panic if `stream_index` is 0.
pub fn configure_bdl<T: RegisterAccess>(
    ctrl: &T,
    stream_index: u8,
    bdl: &DmaRegion,
    pcm_buf: &DmaRegion,
) -> Result<(), AudioError> {
    debug_assert!(stream_index >= 1, "Stream index must be 1-based");
    debug_assert!(bdl.len() >= BDL_ENTRY_SIZE * BDL_ENTRIES, "BDL region too small");

    let total_len = pcm_buf.len();

    // SAFETY: bdl is a valid DMA region allocated for BDL entries.
    // We write exactly BDL_ENTRIES entries.
    unsafe {
        let bdlp = bdl.as_mut_ptr::<BdlEntry>();

        // First entry: points to PCM buffer with IOC flag
        ptr::write_volatile(
            bdlp,
            BdlEntry::new(pcm_buf.phys(), total_len as u32, true),
        );

        // Zero remaining entries
        for i in 1..BDL_ENTRIES {
            let e = bdlp.add(i);
            ptr::write_volatile(e, BdlEntry::zeroed());
        }
    }

    // Program BDL pointer registers
    ctrl.write_stream_reg32(stream_index, SD_BDPL, (bdl.phys() & 0xFFFF_FFFF) as u32);
    ctrl.write_stream_reg32(stream_index, SD_BDPU, (bdl.phys() >> 32) as u32);

    // Set Cyclic Buffer Length (total bytes in all BDL entries)
    ctrl.write_stream_reg32(stream_index, SD_CBL, total_len as u32);

    // Set Last Valid Index (0 = only entry 0 is valid)
    ctrl.write_stream_reg16(stream_index, SD_LVI, 0);

    Ok(())
}

/// Configures a stream's BDL with multiple entries.
/// Debug builds panic if entries exceeds BDL_ENTRIES.
pub fn configure_bdl_multi<T: RegisterAccess>(
    ctrl: &T,
    stream_index: u8,
    bdl: &DmaRegion,
    entries: &[BdlEntry],
) -> Result<u32, AudioError> {
    debug_assert!(stream_index >= 1, "Stream index must be 1-based");
    debug_assert!(entries.len() <= BDL_ENTRIES, "Too many BDL entries");
    debug_assert!(!entries.is_empty(), "At least one BDL entry required");

    let mut total_len: u32 = 0;

    // SAFETY: bdl is a valid DMA region allocated for BDL entries.
    unsafe {
        let bdlp = bdl.as_mut_ptr::<BdlEntry>();

        // Write provided entries
        for (i, entry) in entries.iter().enumerate() {
            ptr::write_volatile(bdlp.add(i), *entry);
            total_len = total_len.saturating_add(entry.len());
        }

        // Zero remaining entries
        for i in entries.len()..BDL_ENTRIES {
            ptr::write_volatile(bdlp.add(i), BdlEntry::zeroed());
        }
    }

    // Program BDL pointer registers
    ctrl.write_stream_reg32(stream_index, SD_BDPL, (bdl.phys() & 0xFFFF_FFFF) as u32);
    ctrl.write_stream_reg32(stream_index, SD_BDPU, (bdl.phys() >> 32) as u32);

    // Set Cyclic Buffer Length
    ctrl.write_stream_reg32(stream_index, SD_CBL, total_len);

    // Set Last Valid Index (0-based index of last valid entry)
    ctrl.write_stream_reg16(stream_index, SD_LVI, (entries.len() - 1) as u16);

    Ok(total_len)
}

// =============================================================================
// Format Configuration
// =============================================================================
/// # Supported Formats
///
/// Currently supports:
/// - Sample rates: 48 kHz, 44.1 kHz
/// - Bit depths: 16-bit
/// - Channels: 1-8
pub fn configure_format<T: RegisterAccess>(
    ctrl: &T,
    stream_index: u8,
    format: &AudioFormat,
) -> Result<(), AudioError> {
    debug_assert!(stream_index >= 1, "Stream index must be 1-based");

    let fmt = format.to_hda_format().ok_or(AudioError::UnsupportedFormat)?;
    ctrl.write_stream_reg16(stream_index, SD_FMT, fmt);
    Ok(())
}

/// Sets the stream number for codec association.
///
/// The stream number links this stream descriptor to codec converter
/// widgets. The codec must be programmed with the same stream number.
pub fn set_stream_number<T: RegisterAccess>(ctrl: &T, stream_index: u8, stream_number: u8) {
    debug_assert!(stream_number >= 1 && stream_number <= 15, "Stream number must be 1-15");

    let mut ctl = ctrl.read_stream_reg32(stream_index, SD_CTL);
    // Clear existing stream number
    ctl &= !(SD_CTL_STRM_MASK << SD_CTL_STRM_SHIFT);
    // Set new stream number
    ctl |= ((stream_number as u32) & SD_CTL_STRM_MASK) << SD_CTL_STRM_SHIFT;
    ctrl.write_stream_reg32(stream_index, SD_CTL, ctl);
}

// =============================================================================
// Interrupt Configuration
// =============================================================================
pub fn enable_interrupts<T: RegisterAccess>(
    ctrl: &T,
    stream_index: u8,
    ioc: bool,
    fifo_error: bool,
    desc_error: bool,
) {
    let mut ctl = ctrl.read_stream_reg32(stream_index, SD_CTL);

    if ioc {
        ctl |= SD_CTL_IOCE;
    }
    if fifo_error {
        ctl |= SD_CTL_FEIE;
    }
    if desc_error {
        ctl |= SD_CTL_DEIE;
    }

    ctrl.write_stream_reg32(stream_index, SD_CTL, ctl);
}

pub fn disable_interrupts<T: RegisterAccess>(ctrl: &T, stream_index: u8) {
    let mut ctl = ctrl.read_stream_reg32(stream_index, SD_CTL);
    ctl &= !(SD_CTL_IOCE | SD_CTL_FEIE | SD_CTL_DEIE);
    ctrl.write_stream_reg32(stream_index, SD_CTL, ctl);
}

// =============================================================================
// Stream Control
// =============================================================================
pub fn start_stream<T: RegisterAccess>(ctrl: &T, stream_index: u8) {
    debug_assert!(stream_index >= 1, "Stream index must be 1-based");

    // Clear status bits
    ctrl.write_stream_reg8(stream_index, SD_STS, SD_STS_BCIS | SD_STS_FIFOE | SD_STS_DESE);

    // Set RUN bit
    let mut ctl = ctrl.read_stream_reg32(stream_index, SD_CTL);
    ctl |= SD_CTL_RUN;
    ctrl.write_stream_reg32(stream_index, SD_CTL, ctl);

    STREAMS_STARTED.fetch_add(1, Ordering::Relaxed);
}

/// Stops a stream (clears the RUN bit).
pub fn stop_stream<T: RegisterAccess>(ctrl: &T, stream_index: u8) {
    debug_assert!(stream_index >= 1, "Stream index must be 1-based");

    let mut ctl = ctrl.read_stream_reg32(stream_index, SD_CTL);
    ctl &= !SD_CTL_RUN;
    ctrl.write_stream_reg32(stream_index, SD_CTL, ctl);

    // Wait for stream to stop
    spin_while(|| is_stream_running(ctrl, stream_index), SPIN_TIMEOUT_SHORT);

    STREAMS_STOPPED.fetch_add(1, Ordering::Relaxed);
}

// =============================================================================
// Status Queries
// =============================================================================
#[inline]
pub fn is_stream_running<T: RegisterAccess>(ctrl: &T, stream_index: u8) -> bool {
    (ctrl.read_stream_reg32(stream_index, SD_CTL) & SD_CTL_RUN) != 0
}

/// Gets the current stream state.
pub fn get_stream_state<T: RegisterAccess>(ctrl: &T, stream_index: u8) -> StreamState {
    let ctl = ctrl.read_stream_reg32(stream_index, SD_CTL);
    let sts = ctrl.read_stream_reg8(stream_index, SD_STS);

    // Check for errors
    if (sts & (SD_STS_FIFOE | SD_STS_DESE)) != 0 {
        return StreamState::Error;
    }

    // Check reset state
    if (ctl & SD_CTL_SRST) != 0 {
        return StreamState::Resetting;
    }

    // Check run state
    if (ctl & SD_CTL_RUN) != 0 {
        return StreamState::Running;
    }

    // Check if configured (CBL > 0)
    let cbl = ctrl.read_stream_reg32(stream_index, SD_CBL);
    if cbl > 0 {
        return StreamState::Ready;
    }

    StreamState::Stopped
}

/// Gets the current link position in the buffer.
#[inline]
pub fn get_link_position<T: RegisterAccess>(ctrl: &T, stream_index: u8) -> u32 {
    ctrl.read_stream_reg32(stream_index, SD_LPIB)
}

/// Gets the cyclic buffer length.
#[inline]
pub fn get_buffer_length<T: RegisterAccess>(ctrl: &T, stream_index: u8) -> u32 {
    ctrl.read_stream_reg32(stream_index, SD_CBL)
}

/// Gets the stream status register.
#[inline]
pub fn get_stream_status<T: RegisterAccess>(ctrl: &T, stream_index: u8) -> u8 {
    ctrl.read_stream_reg8(stream_index, SD_STS)
}

/// Clears stream status bits.
pub fn clear_stream_status<T: RegisterAccess>(ctrl: &T, stream_index: u8, bits: u8) {
    ctrl.write_stream_reg8(stream_index, SD_STS, bits);
}

pub fn check_stream_errors<T: RegisterAccess>(ctrl: &T, stream_index: u8) -> Result<(), AudioError> {
    let sts = get_stream_status(ctrl, stream_index);

    if (sts & SD_STS_FIFOE) != 0 {
        clear_stream_status(ctrl, stream_index, SD_STS_FIFOE);
        STREAM_ERRORS.fetch_add(1, Ordering::Relaxed);
        return Err(AudioError::StreamFifoError);
    }

    if (sts & SD_STS_DESE) != 0 {
        clear_stream_status(ctrl, stream_index, SD_STS_DESE);
        STREAM_ERRORS.fetch_add(1, Ordering::Relaxed);
        return Err(AudioError::StreamDescriptorError);
    }

    Ok(())
}

// =============================================================================
// Playback Control
// =============================================================================

pub fn wait_playback_complete<T: RegisterAccess>(
    ctrl: &T,
    stream_index: u8,
) -> Result<(), AudioError> {
    let cbl = get_buffer_length(ctrl, stream_index);

    if cbl == 0 {
        return Err(AudioError::StreamNotConfigured);
    }

    if !spin_until(
        || get_link_position(ctrl, stream_index) >= cbl,
        SPIN_TIMEOUT_LONG,
    ) {
        return Err(AudioError::PlaybackTimeout);
    }

    Ok(())
}

pub fn wait_buffer_complete<T: RegisterAccess>(
    ctrl: &T,
    stream_index: u8,
) -> Result<(), AudioError> {
    if !spin_until(
        || (get_stream_status(ctrl, stream_index) & SD_STS_BCIS) != 0,
        SPIN_TIMEOUT_LONG,
    ) {
        return Err(AudioError::PlaybackTimeout);
    }

    clear_stream_status(ctrl, stream_index, SD_STS_BCIS);
    check_stream_errors(ctrl, stream_index)?;

    Ok(())
}

/// _*
/// Full Stream Setup:
/// This is a convenience function that performs all necessary setup:
/// 1. Reset the stream
/// 2. Configure BDL
/// 3. Configure format
/// 4. Set stream number
/// 5. Enable interrupts _*

pub fn init_output_stream<T: RegisterAccess>(
    ctrl: &T,
    stream_index: u8,
    bdl: &DmaRegion,
    pcm_buf: &DmaRegion,
    format: &AudioFormat,
) -> Result<(), AudioError> {
    reset_stream(ctrl, stream_index)?;
    configure_bdl(ctrl, stream_index, bdl, pcm_buf)?;
    configure_format(ctrl, stream_index, format)?;
    set_stream_number(ctrl, stream_index, stream_index);
    enable_interrupts(ctrl, stream_index, true, true, true);
    Ok(())
}

pub fn shutdown_stream<T: RegisterAccess>(ctrl: &T, stream_index: u8) {
    // Stop the stream if running
    if is_stream_running(ctrl, stream_index) {
        stop_stream(ctrl, stream_index);
    }

    disable_interrupts(ctrl, stream_index);
    let _ = reset_stream(ctrl, stream_index);
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_state_enum() {
        assert!(StreamState::Running.is_active());
        assert!(!StreamState::Stopped.is_active());
        assert!(StreamState::Stopped.can_start());
        assert!(StreamState::Ready.can_start());
        assert!(!StreamState::Running.can_start());
        assert!(StreamState::Error.is_error());
    }

    #[test]
    fn test_statistics() {
        reset_stream_stats();
        assert_eq!(streams_started_count(), 0);
        assert_eq!(streams_stopped_count(), 0);
        assert_eq!(stream_error_count(), 0);
    }
}
