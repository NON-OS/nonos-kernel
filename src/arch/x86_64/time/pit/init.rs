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

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use super::constants::DEFAULT_FREQUENCY;
use super::types::{PitError, PitResult, Mode};
use super::state::{INITIALIZED, CHANNELS};
use super::timer::init_system_timer;
use super::speaker::disable_speaker;

pub fn init() -> PitResult<()> {
    init_with_frequency(DEFAULT_FREQUENCY)
}

pub fn init_with_frequency(frequency_hz: u32) -> PitResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(PitError::AlreadyInitialized);
    }

    init_system_timer(frequency_hz)?;

    Ok(())
}

pub fn init_pit(freq_hz: u32) {
    let _ = init_with_frequency(freq_hz);
}

pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Relaxed)
}

pub fn reset() -> PitResult<()> {
    disable_speaker();

    {
        let mut channels = CHANNELS.write();
        for channel in channels.iter_mut() {
            channel.configured = false;
            channel.mode = Mode::RateGenerator;
            channel.divisor = 0;
            channel.frequency_hz = 0;
            channel.tick_count = AtomicU64::new(0);
            channel.oneshot_pending = AtomicBool::new(false);
        }
    }

    INITIALIZED.store(false, Ordering::SeqCst);

    Ok(())
}
