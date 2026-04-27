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

use super::core::VirtioRngDevice;

impl VirtioRngDevice {
    pub(in crate::drivers::virtio_rng) fn get_random_bytes(
        &mut self,
        buf: &mut [u8],
    ) -> Result<usize, &'static str> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.queue.request_random(buf.len().min(4096))?;
        let mut timeout = 100_000u32;
        while !self.queue.has_completed() && timeout > 0 {
            core::hint::spin_loop();
            timeout -= 1;
        }
        if timeout == 0 {
            return Err("virtio-rng: timeout");
        }
        let received = self.queue.get_received_bytes(buf);
        Ok(received)
    }
}
