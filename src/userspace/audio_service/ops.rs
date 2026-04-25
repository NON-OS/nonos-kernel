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

extern crate alloc;

use crate::drivers::audio;
use crate::services::ServiceResponse;
use alloc::vec::Vec;

const ERR_AUDIO: i32 = -101;

pub(super) fn audio_init(seq: u32) -> ServiceResponse {
    match audio::init_hd_audio() {
        Ok(()) => ServiceResponse::ok(seq, Vec::new()),
        Err(_) => ServiceResponse::err(seq, ERR_AUDIO),
    }
}

pub(super) fn audio_play(seq: u32, data: &[u8]) -> ServiceResponse {
    if let Some(ctrl) = audio::get_controller() {
        if ctrl.play_pcm(data).is_ok() {
            return ServiceResponse::ok(seq, Vec::new());
        }
    }
    ServiceResponse::err(seq, ERR_AUDIO)
}

pub(super) fn audio_pause(seq: u32) -> ServiceResponse {
    if let Some(ctrl) = audio::get_controller() {
        if ctrl.set_mute(true).is_ok() {
            return ServiceResponse::ok(seq, Vec::new());
        }
    }
    ServiceResponse::err(seq, ERR_AUDIO)
}

pub(super) fn audio_resume(seq: u32) -> ServiceResponse {
    if let Some(ctrl) = audio::get_controller() {
        if ctrl.set_mute(false).is_ok() {
            return ServiceResponse::ok(seq, Vec::new());
        }
    }
    ServiceResponse::err(seq, ERR_AUDIO)
}

pub(super) fn audio_stop(seq: u32) -> ServiceResponse {
    if let Some(ctrl) = audio::get_controller() {
        if ctrl.shutdown().is_ok() {
            return ServiceResponse::ok(seq, Vec::new());
        }
    }
    ServiceResponse::err(seq, ERR_AUDIO)
}

pub(super) fn audio_status(seq: u32) -> ServiceResponse {
    let init = audio::is_initialized();
    ServiceResponse::ok(seq, alloc::vec![init as u8])
}
