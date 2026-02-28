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

use super::types::TestResult;
use crate::arch::x86_64::time::pit;

pub fn test_pit_constants() -> TestResult {
    if pit::PIT_FREQUENCY != 1193182 {
        return TestResult::Failed;
    }

    if pit::MAX_DIVISOR != 65535 {
        return TestResult::Failed;
    }
    if pit::MIN_DIVISOR != 1 {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_pit_freq_to_divisor() -> TestResult {
    match pit::frequency_to_divisor(1000) {
        Ok(divisor) => {
            if divisor < 1190 || divisor > 1196 {
                return TestResult::Failed;
            }
        }
        Err(_) => return TestResult::Failed,
    }

    match pit::frequency_to_divisor(100) {
        Ok(divisor) => {
            if divisor < 11920 || divisor > 11940 {
                return TestResult::Failed;
            }
        }
        Err(_) => return TestResult::Failed,
    }

    TestResult::Passed
}

pub fn test_pit_divisor_to_freq() -> TestResult {
    let freq = pit::divisor_to_frequency(1193);
    if freq < 990 || freq > 1010 {
        return TestResult::Failed;
    }

    let freq_zero = pit::divisor_to_frequency(0);
    if freq_zero != 0 {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_pit_period_ns() -> TestResult {
    let period = pit::divisor_to_period_ns(1193);

    if period < 950_000 || period > 1_050_000 {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_pit_invalid_frequency() -> TestResult {
    if pit::frequency_to_divisor(0).is_ok() {
        return TestResult::Failed;
    }

    if pit::frequency_to_divisor(2_000_000).is_ok() {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_pit_channels() -> TestResult {
    if pit::Channel::Channel0.data_port() != 0x40 {
        return TestResult::Failed;
    }
    if pit::Channel::Channel1.data_port() != 0x41 {
        return TestResult::Failed;
    }
    if pit::Channel::Channel2.data_port() != 0x42 {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_pit_modes() -> TestResult {
    if !pit::Mode::RateGenerator.is_periodic() {
        return TestResult::Failed;
    }
    if !pit::Mode::SquareWave.is_periodic() {
        return TestResult::Failed;
    }

    if !pit::Mode::InterruptOnTerminal.is_oneshot() {
        return TestResult::Failed;
    }

    TestResult::Passed
}

pub fn test_pit_best_divisor() -> TestResult {
    match pit::find_best_divisor(1000) {
        Some((divisor, actual_freq, error)) => {
            if divisor == 0 || divisor > 65535 {
                return TestResult::Failed;
            }
            if actual_freq < 990 || actual_freq > 1010 {
                return TestResult::Failed;
            }
            if error.abs() > 10 {
                return TestResult::Failed;
            }
            TestResult::Passed
        }
        None => TestResult::Failed,
    }
}
