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

use super::types::{AccessMode, LEG_STATUS};
use crate::drivers::virtio_rng::queue::RngQueue;

pub(in crate::drivers::virtio_rng) struct VirtioRngDevice {
    pub(super) access: AccessMode,
    pub(super) queue: RngQueue,
}

impl VirtioRngDevice {
    pub(in crate::drivers::virtio_rng) fn from_bar0(bar0: u32) -> Result<Self, &'static str> {
        if bar0 == 0 {
            return Err("virtio-rng: BAR0 is zero");
        }
        let access = if bar0 & 1 != 0 {
            AccessMode::Io((bar0 & 0xFFFC) as u16)
        } else {
            AccessMode::Mmio((bar0 & 0xFFFFFFF0) as u64)
        };
        let queue = RngQueue::new()?;
        let mut dev = Self { access, queue };
        dev.init_legacy()?;
        Ok(dev)
    }
}

impl Drop for VirtioRngDevice {
    fn drop(&mut self) {
        self.write8(LEG_STATUS, 0);
    }
}
