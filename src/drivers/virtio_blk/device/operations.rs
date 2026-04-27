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

use super::core::VirtioBlkDevice;
use crate::drivers::virtio_blk::constants::DEFAULT_TIMEOUT_MS;
use crate::drivers::virtio_blk::types::BlkError;

impl VirtioBlkDevice {
    pub(super) fn wait_completion(&self) -> Result<(), BlkError> {
        let start = crate::time::current_ticks();
        let timeout_ticks = (DEFAULT_TIMEOUT_MS as u64) * 1000;
        while !self.queue.has_completed() {
            if crate::time::current_ticks() - start > timeout_ticks {
                return Err(BlkError::Timeout);
            }
            core::hint::spin_loop();
        }
        Ok(())
    }
}
