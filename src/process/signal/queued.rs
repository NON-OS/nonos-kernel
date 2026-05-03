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

use super::siginfo::SigInfo;

#[derive(Debug, Clone)]
pub struct QueuedSignal {
    pub signo: u8,
    pub info: SigInfo,
    pub timestamp: u64,
}

impl QueuedSignal {
    pub fn new(signo: u8, info: SigInfo) -> Self {
        Self { signo, info, timestamp: crate::time::monotonic_ns() }
    }

    pub fn signal_number(&self) -> u8 {
        self.signo
    }

    pub fn signal_info(&self) -> &SigInfo {
        &self.info
    }

    pub fn age_ns(&self) -> u64 {
        crate::time::monotonic_ns().saturating_sub(self.timestamp)
    }
}
