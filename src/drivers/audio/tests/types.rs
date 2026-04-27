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

use crate::drivers::audio::types::*;
use crate::test::framework::TestResult;

pub(crate) fn test_bdl_entry_size() -> TestResult {
    if core::mem::size_of::<BdlEntry>() != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bdl_entry_new() -> TestResult {
    let entry = BdlEntry::new(0x1234_5678_9ABC_DE80, 4096, true);
    if { entry.addr_lo } != 0x9ABC_DE80 {
        return TestResult::Fail;
    }
    if { entry.addr_hi } != 0x1234_5678 {
        return TestResult::Fail;
    }
    if { entry.length } != 4096 {
        return TestResult::Fail;
    }
    if { entry.flags } != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bdl_entry_zeroed() -> TestResult {
    let entry = BdlEntry::zeroed();
    if { entry.addr_lo } != 0 {
        return TestResult::Fail;
    }
    if { entry.addr_hi } != 0 {
        return TestResult::Fail;
    }
    if { entry.length } != 0 {
        return TestResult::Fail;
    }
    if { entry.flags } != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bdl_entry_phys_addr() -> TestResult {
    let entry = BdlEntry::new(0xDEAD_BEEF_CAFE_BA80, 512, false);
    if entry.phys_addr() != 0xDEAD_BEEF_CAFE_BA80 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audio_stats_default() -> TestResult {
    let stats = AudioStats::default();
    if stats.samples_played != 0 {
        return TestResult::Fail;
    }
    if stats.samples_recorded != 0 {
        return TestResult::Fail;
    }
    if stats.buffer_underruns != 0 {
        return TestResult::Fail;
    }
    if stats.buffer_overruns != 0 {
        return TestResult::Fail;
    }
    if stats.interrupts_handled != 0 {
        return TestResult::Fail;
    }
    if stats.active_streams != 0 {
        return TestResult::Fail;
    }
    if stats.codecs_detected != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audio_stats_copy() -> TestResult {
    let stats1 = AudioStats {
        samples_played: 1000,
        samples_recorded: 500,
        buffer_underruns: 2,
        buffer_overruns: 1,
        interrupts_handled: 100,
        active_streams: 1,
        codecs_detected: 2,
        bytes_transferred: 4000,
        error_count: 0,
    };

    let stats2 = stats1;
    if stats1.samples_played != stats2.samples_played {
        return TestResult::Fail;
    }
    if stats1.codecs_detected != stats2.codecs_detected {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audio_format_default() -> TestResult {
    let format = AudioFormat::default();
    if format.sample_rate != 48_000 {
        return TestResult::Fail;
    }
    if format.bits_per_sample != 16 {
        return TestResult::Fail;
    }
    if format.channels != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audio_format_bytes_per_sample() -> TestResult {
    let format = AudioFormat::new(48_000, 16, 2);
    if format.bytes_per_sample() != 4 {
        return TestResult::Fail;
    }

    let format_mono = AudioFormat::new(44_100, 16, 1);
    if format_mono.bytes_per_sample() != 2 {
        return TestResult::Fail;
    }

    let format_24bit = AudioFormat::new(48_000, 24, 2);
    if format_24bit.bytes_per_sample() != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audio_format_bytes_per_second() -> TestResult {
    let format = AudioFormat::new(48_000, 16, 2);
    if format.bytes_per_second() != 192_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audio_format_to_hda() -> TestResult {
    let format = AudioFormat::new(48_000, 16, 2);
    let hda_fmt = format.to_hda_format();
    if hda_fmt.is_none() {
        return TestResult::Fail;
    }

    let unsupported = AudioFormat::new(22_050, 16, 2);
    if unsupported.to_hda_format().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stream_state_default() -> TestResult {
    let state = StreamState::default();
    if state != StreamState::Stopped {
        return TestResult::Fail;
    }
    TestResult::Pass
}
