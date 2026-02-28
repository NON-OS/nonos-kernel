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

use core::sync::atomic::Ordering;
use super::{ports, system_control};
use super::types::{PitResult, Channel, Mode};
use super::state::{CHANNELS, STATS_SPEAKER_BEEPS};
use super::io::{inb, outb, configure_channel_raw};
use super::conversion::frequency_to_divisor;
use super::sleep::pit_sleep_ms;

pub(super) fn enable_channel2_gate() {
    // SAFETY: Writing to system control port to enable channel 2 gate.
    unsafe {
        let control = inb(ports::SYSTEM_CONTROL_B);
        outb(ports::SYSTEM_CONTROL_B, control | system_control::TIMER2_GATE);
    }
}

pub(super) fn get_channel2_output() -> bool {
    // SAFETY: Reading system control port to check channel 2 output.
    unsafe { (inb(ports::SYSTEM_CONTROL_B) & system_control::TIMER2_OUTPUT) != 0 }
}

pub(super) fn enable_speaker() {
    // SAFETY: Writing to system control port to enable speaker.
    unsafe {
        let control = inb(ports::SYSTEM_CONTROL_B);
        outb(
            ports::SYSTEM_CONTROL_B,
            control | system_control::SPEAKER_ENABLE | system_control::TIMER2_GATE,
        );
    }
}

pub(super) fn disable_speaker() {
    // SAFETY: Writing to system control port to disable speaker.
    unsafe {
        let control = inb(ports::SYSTEM_CONTROL_B);
        outb(
            ports::SYSTEM_CONTROL_B,
            control & !(system_control::SPEAKER_ENABLE | system_control::TIMER2_GATE),
        );
    }
}

pub fn beep(frequency_hz: u32, duration_ms: u32) -> PitResult<()> {
    let divisor = frequency_to_divisor(frequency_hz)?;

    configure_channel_raw(Channel::Channel2, Mode::SquareWave, divisor);

    enable_speaker();

    STATS_SPEAKER_BEEPS.fetch_add(1, Ordering::Relaxed);

    pit_sleep_ms(duration_ms as u64);

    disable_speaker();

    Ok(())
}

pub fn start_tone(frequency_hz: u32) -> PitResult<()> {
    let divisor = frequency_to_divisor(frequency_hz)?;

    configure_channel_raw(Channel::Channel2, Mode::SquareWave, divisor);
    enable_speaker();

    {
        let mut channels = CHANNELS.write();
        channels[2].configured = true;
        channels[2].mode = Mode::SquareWave;
        channels[2].divisor = divisor;
        channels[2].frequency_hz = frequency_hz;
    }

    STATS_SPEAKER_BEEPS.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

pub fn stop_tone() {
    disable_speaker();

    let mut channels = CHANNELS.write();
    channels[2].configured = false;
}
