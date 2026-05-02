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

use super::backend;
use super::buffer::DmaBuffer;

impl DmaBuffer {
    /// Pre-DMA window. After this returns, every CPU write to the buffer
    /// is observable to the device. Issue immediately before the doorbell.
    #[inline]
    pub fn sync_for_device(&self) {
        backend::sync_for_device(self.cpu_addr, self.size, self.direction, self.coherency);
    }

    /// Post-DMA window. After this returns, every device write to the
    /// buffer is observable to the CPU. Issue after the device signals
    /// completion and before reading the buffer.
    #[inline]
    pub fn sync_for_cpu(&self) {
        backend::sync_for_cpu(self.cpu_addr, self.size, self.direction, self.coherency);
    }
}
