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

use crate::drivers::virtio_blk::constants::LEG_STATUS;
use crate::drivers::virtio_blk::queue::BlkQueue;
use crate::drivers::virtio_blk::types::{AccessMode, VirtioBlkConfig};

pub(crate) struct VirtioBlkDevice {
    pub(super) access: AccessMode,
    pub(super) queue: BlkQueue,
    pub(super) capacity: u64,
    pub(super) read_only: bool,
    pub(super) initialized: bool,
    pub(super) config: VirtioBlkConfig,
    pub(super) supports_flush: bool,
    pub(super) supports_discard: bool,
    pub(super) supports_geometry: bool,
}

impl VirtioBlkDevice {
    pub(crate) fn from_bar0(bar0: u32) -> Result<Self, &'static str> {
        if bar0 == 0 {
            return Err("virtio-blk: BAR0 is zero");
        }
        let access = if bar0 & 1 != 0 {
            AccessMode::Io((bar0 & 0xFFFC) as u16)
        } else {
            AccessMode::Mmio((bar0 & 0xFFFFFFF0) as u64)
        };
        let queue = BlkQueue::new()?;
        let cfg = VirtioBlkConfig::default();
        let mut dev = Self {
            access,
            queue,
            capacity: 0,
            read_only: false,
            initialized: false,
            config: cfg,
            supports_flush: false,
            supports_discard: false,
            supports_geometry: false,
        };
        dev.init_legacy()?;
        Ok(dev)
    }

    pub(crate) fn sector_count(&self) -> u64 {
        self.capacity
    }
    pub(crate) fn is_read_only(&self) -> bool {
        self.read_only
    }
    pub(crate) fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Drop for VirtioBlkDevice {
    fn drop(&mut self) {
        self.write8(LEG_STATUS, 0);
    }
}
