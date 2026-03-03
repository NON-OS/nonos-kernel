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

use core::fmt;

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct AudioStats {
    pub samples_played: u64,
    pub samples_recorded: u64,
    pub buffer_underruns: u64,
    pub buffer_overruns: u64,
    pub interrupts_handled: u64,
    pub active_streams: u64,
    pub codecs_detected: u32,
    pub bytes_transferred: u64,
    pub error_count: u64,
}

impl AudioStats {
    pub const fn new() -> Self {
        Self {
            samples_played: 0,
            samples_recorded: 0,
            buffer_underruns: 0,
            buffer_overruns: 0,
            interrupts_handled: 0,
            active_streams: 0,
            codecs_detected: 0,
            bytes_transferred: 0,
            error_count: 0,
        }
    }

    pub const fn has_errors(&self) -> bool {
        self.buffer_underruns > 0 || self.buffer_overruns > 0 || self.error_count > 0
    }

    pub const fn total_errors(&self) -> u64 {
        self.buffer_underruns + self.buffer_overruns + self.error_count
    }
}

impl fmt::Display for AudioStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AudioStats {{ samples: {}, codecs: {}, streams: {}, errors: {} }}",
            self.samples_played,
            self.codecs_detected,
            self.active_streams,
            self.total_errors()
        )
    }
}
