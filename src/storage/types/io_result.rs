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

use super::enums::IoStatus;

#[derive(Clone, Copy, Debug, Default)]
pub struct IoResult {
    pub status: IoStatus,
    pub bytes_transferred: usize,
    pub error_code: u32,
    pub completion_time: u64,
}

impl IoResult {
    pub fn status(&self) -> IoStatus {
        self.status
    }
    pub fn bytes_transferred(&self) -> usize {
        self.bytes_transferred
    }
    pub fn error_code(&self) -> u32 {
        self.error_code
    }
    pub fn completion_time(&self) -> u64 {
        self.completion_time
    }
    pub fn is_success(&self) -> bool {
        matches!(self.status, IoStatus::Success | IoStatus::Completed)
    }
}

pub type IoCompletionCallback = fn(IoResult);
