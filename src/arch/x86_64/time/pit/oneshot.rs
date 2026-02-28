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
use super::types::{PitError, PitResult, Channel, Mode};
use super::state::{CHANNELS, STATS_ONESHOT_COMPLETED};
use super::io::configure_channel_raw;
use super::conversion::period_us_to_divisor;
use super::speaker::{enable_channel2_gate, get_channel2_output};

pub fn start_oneshot(duration_us: u32) -> PitResult<()> {
    let divisor = period_us_to_divisor(duration_us)?;

    {
        let channels = CHANNELS.read();
        if channels[2].oneshot_pending.load(Ordering::Relaxed) {
            return Err(PitError::OneShotPending);
        }
    }

    configure_channel_raw(Channel::Channel2, Mode::InterruptOnTerminal, divisor);

    {
        let mut channels = CHANNELS.write();
        channels[2].configured = true;
        channels[2].mode = Mode::InterruptOnTerminal;
        channels[2].divisor = divisor;
        channels[2].oneshot_pending.store(true, Ordering::Relaxed);
    }

    enable_channel2_gate();

    Ok(())
}

pub fn wait_oneshot() -> PitResult<()> {
    let mut timeout = 1_000_000u32;
    while get_channel2_output() && timeout > 0 {
        timeout -= 1;
        core::hint::spin_loop();
    }

    if timeout == 0 {
        return Err(PitError::Timeout);
    }

    {
        let channels = CHANNELS.read();
        channels[2].oneshot_pending.store(false, Ordering::Relaxed);
    }

    STATS_ONESHOT_COMPLETED.fetch_add(1, Ordering::Relaxed);

    Ok(())
}

pub fn oneshot_delay_us(duration_us: u32) -> PitResult<()> {
    start_oneshot(duration_us)?;
    wait_oneshot()
}
