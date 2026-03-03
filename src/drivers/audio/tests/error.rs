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

use super::super::error::*;

#[test]
fn test_audio_error_display() {
    assert_eq!(AudioError::Bar0NotMmio.as_str(), "HDA BAR0 is not MMIO");
    assert_eq!(AudioError::NoControllerFound.as_str(), "No HD Audio controller found");
    assert_eq!(AudioError::PlaybackTimeout.as_str(), "Playback did not complete in time");
    assert_eq!(AudioError::UnsupportedFormat.as_str(), "Unsupported PCM format");
}

#[test]
fn test_audio_error_variants() {
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

    assert_eq!(errors.len(), 18);

    for err in &errors {
        assert!(!err.as_str().is_empty());
    }
}

#[test]
fn test_audio_error_equality() {
    assert_eq!(AudioError::Bar0NotMmio, AudioError::Bar0NotMmio);
    assert_ne!(AudioError::Bar0NotMmio, AudioError::NoControllerFound);

    let err1 = AudioError::PlaybackTimeout;
    let err2 = err1;
    assert_eq!(err1, err2);
}

#[test]
fn test_audio_error_from_str() {
    let err: AudioError = "HDA BAR0 is not MMIO".into();
    assert_eq!(err, AudioError::Bar0NotMmio);

    let err: AudioError = "No HD Audio controller found".into();
    assert_eq!(err, AudioError::NoControllerFound);

    let err: AudioError = "Unknown error".into();
    assert_eq!(err, AudioError::NotInitialized);
}
