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


use core::ptr;

use super::super::error::AudioError;
use super::super::types::{BdlEntry, DmaRegion, AudioFormat};

#[cfg(test)]
use super::super::types::StreamState;
use super::super::constants::*;
use super::helpers::{RegisterAccess, spin_until, spin_while};

pub(super) fn reset_stream<T: RegisterAccess>(ctrl: &T, stream_index: u8) -> Result<(), AudioError> {
    debug_assert!(stream_index >= 1, "Stream index must be 1-based");

    ctrl.write_stream_reg8(stream_index, SD_STS, 0xFF);

    let mut ctl = ctrl.read_stream_reg32(stream_index, SD_CTL);
    ctl |= SD_CTL_SRST;
    ctrl.write_stream_reg32(stream_index, SD_CTL, ctl);

    if !spin_until(
        || (ctrl.read_stream_reg32(stream_index, SD_CTL) & SD_CTL_SRST) != 0,
        SPIN_TIMEOUT_SHORT,
    ) {
        return Err(AudioError::StreamResetSetTimeout);
    }

    let mut ctl = ctrl.read_stream_reg32(stream_index, SD_CTL);
    ctl &= !SD_CTL_SRST;
    ctrl.write_stream_reg32(stream_index, SD_CTL, ctl);

    if !spin_while(
        || (ctrl.read_stream_reg32(stream_index, SD_CTL) & SD_CTL_SRST) != 0,
        SPIN_TIMEOUT_SHORT,
    ) {
        return Err(AudioError::StreamResetClearTimeout);
    }

    Ok(())
}

pub(super) fn configure_bdl<T: RegisterAccess>(
    ctrl: &T,
    stream_index: u8,
    bdl: &DmaRegion,
    pcm_buf: &DmaRegion,
) -> Result<(), AudioError> {
    debug_assert!(stream_index >= 1, "Stream index must be 1-based");
    debug_assert!(bdl.len() >= BDL_ENTRY_SIZE * BDL_ENTRIES, "BDL region too small");

    let total_len = pcm_buf.len();

    // SAFETY: bdl is valid DMA region allocated for BDL entries, writing exactly BDL_ENTRIES entries
    unsafe {
        let bdlp = bdl.as_mut_ptr::<BdlEntry>();

        ptr::write_volatile(
            bdlp,
            BdlEntry::new(pcm_buf.phys(), total_len as u32, true),
        );

        for i in 1..BDL_ENTRIES {
            let e = bdlp.add(i);
            ptr::write_volatile(e, BdlEntry::zeroed());
        }
    }

    ctrl.write_stream_reg32(stream_index, SD_BDPL, (bdl.phys() & 0xFFFF_FFFF) as u32);
    ctrl.write_stream_reg32(stream_index, SD_BDPU, (bdl.phys() >> 32) as u32);
    ctrl.write_stream_reg32(stream_index, SD_CBL, total_len as u32);
    ctrl.write_stream_reg16(stream_index, SD_LVI, 0);

    Ok(())
}

pub(super) fn configure_format<T: RegisterAccess>(
    ctrl: &T,
    stream_index: u8,
    format: &AudioFormat,
) -> Result<(), AudioError> {
    debug_assert!(stream_index >= 1, "Stream index must be 1-based");

    let fmt = format.to_hda_format().ok_or(AudioError::UnsupportedFormat)?;
    ctrl.write_stream_reg16(stream_index, SD_FMT, fmt);
    Ok(())
}

pub(super) fn set_stream_number<T: RegisterAccess>(ctrl: &T, stream_index: u8, stream_number: u8) {
    debug_assert!(stream_number >= 1 && stream_number <= 15, "Stream number must be 1-15");

    let mut ctl = ctrl.read_stream_reg32(stream_index, SD_CTL);
    ctl &= !(SD_CTL_STRM_MASK << SD_CTL_STRM_SHIFT);
    ctl |= ((stream_number as u32) & SD_CTL_STRM_MASK) << SD_CTL_STRM_SHIFT;
    ctrl.write_stream_reg32(stream_index, SD_CTL, ctl);
}

pub(super) fn enable_interrupts<T: RegisterAccess>(
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

pub(super) fn start_stream<T: RegisterAccess>(ctrl: &T, stream_index: u8) {
    debug_assert!(stream_index >= 1, "Stream index must be 1-based");

    ctrl.write_stream_reg8(stream_index, SD_STS, SD_STS_BCIS | SD_STS_FIFOE | SD_STS_DESE);

    let mut ctl = ctrl.read_stream_reg32(stream_index, SD_CTL);
    ctl |= SD_CTL_RUN;
    ctrl.write_stream_reg32(stream_index, SD_CTL, ctl);
}

pub(super) fn stop_stream<T: RegisterAccess>(ctrl: &T, stream_index: u8) {
    debug_assert!(stream_index >= 1, "Stream index must be 1-based");

    let mut ctl = ctrl.read_stream_reg32(stream_index, SD_CTL);
    ctl &= !SD_CTL_RUN;
    ctrl.write_stream_reg32(stream_index, SD_CTL, ctl);

    spin_while(|| is_stream_running(ctrl, stream_index), SPIN_TIMEOUT_SHORT);
}

#[inline]
pub(super) fn is_stream_running<T: RegisterAccess>(ctrl: &T, stream_index: u8) -> bool {
    (ctrl.read_stream_reg32(stream_index, SD_CTL) & SD_CTL_RUN) != 0
}

pub(super) fn init_output_stream<T: RegisterAccess>(
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

pub(super) fn wait_playback_complete<T: RegisterAccess>(
    ctrl: &T,
    stream_index: u8,
) -> Result<(), AudioError> {
    if !spin_until(
        || (ctrl.read_stream_reg8(stream_index, SD_STS) & SD_STS_BCIS) != 0,
        SPIN_TIMEOUT_LONG,
    ) {
        return Err(AudioError::PlaybackTimeout);
    }

    ctrl.write_stream_reg8(stream_index, SD_STS, SD_STS_BCIS);
    Ok(())
}

pub(super) fn init_input_stream<T: RegisterAccess>(
    ctrl: &T,
    stream_index: u8,
    bdl: &DmaRegion,
    pcm_buf: &DmaRegion,
    format: &AudioFormat,
) -> Result<(), AudioError> {
    reset_stream(ctrl, stream_index)?;
    configure_bdl(ctrl, stream_index, bdl, pcm_buf)?;
    configure_format(ctrl, stream_index, format)?;
    set_stream_number(ctrl, stream_index, 1);
    enable_interrupts(ctrl, stream_index, true, true, true);

    Ok(())
}

pub(super) fn wait_record_complete<T: RegisterAccess>(
    ctrl: &T,
    stream_index: u8,
) -> Result<(), AudioError> {
    if !spin_until(
        || (ctrl.read_stream_reg8(stream_index, SD_STS) & SD_STS_BCIS) != 0,
        SPIN_TIMEOUT_LONG,
    ) {
        return Err(AudioError::RecordingTimeout);
    }

    ctrl.write_stream_reg8(stream_index, SD_STS, SD_STS_BCIS);
    Ok(())
}

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
}
