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

use crate::drivers::audio::error::*;
use crate::test::framework::TestResult;

pub(crate) fn test_audio_error_display() -> TestResult {
    if AudioError::Bar0NotMmio.as_str() != "HDA BAR0 is not MMIO" {
        return TestResult::Fail;
    }
    if AudioError::NoControllerFound.as_str() != "No HD Audio controller found" {
        return TestResult::Fail;
    }
    if AudioError::PlaybackTimeout.as_str() != "Playback did not complete in time" {
        return TestResult::Fail;
    }
    if AudioError::UnsupportedFormat.as_str() != "Unsupported PCM format" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audio_error_variants() -> TestResult {
    let errors = [
        AudioError::Bar0NotMmio,
        AudioError::CrstClearTimeout,
        AudioError::CrstSetTimeout,
        AudioError::DmaAllocationFailed,
        AudioError::NoControllerFound,
        AudioError::NoCodecPresent,
        AudioError::ImmediateCmdBusy,
        AudioError::ImmediateResponseTimeout,
        AudioError::CorbRirbTimeout,
        AudioError::StreamResetSetTimeout,
        AudioError::StreamResetClearTimeout,
        AudioError::UnsupportedFormat,
        AudioError::PlaybackTimeout,
        AudioError::NotInitialized,
        AudioError::StreamNotConfigured,
        AudioError::InvalidStreamIndex,
        AudioError::BufferTooLarge,
        AudioError::CodecInitFailed,
    ];

    if errors.len() != 18 {
        return TestResult::Fail;
    }

    for err in &errors {
        if err.as_str().is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_audio_error_equality() -> TestResult {
    if AudioError::Bar0NotMmio != AudioError::Bar0NotMmio {
        return TestResult::Fail;
    }
    if AudioError::Bar0NotMmio == AudioError::NoControllerFound {
        return TestResult::Fail;
    }

    let err1 = AudioError::PlaybackTimeout;
    let err2 = err1;
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audio_error_from_str() -> TestResult {
    let err: AudioError = "HDA BAR0 is not MMIO".into();
    if err != AudioError::Bar0NotMmio {
        return TestResult::Fail;
    }

    let err: AudioError = "No HD Audio controller found".into();
    if err != AudioError::NoControllerFound {
        return TestResult::Fail;
    }

    let err: AudioError = "Unknown error".into();
    if err != AudioError::NotInitialized {
        return TestResult::Fail;
    }
    TestResult::Pass
}
