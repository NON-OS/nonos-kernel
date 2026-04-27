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
use super::types::*;

impl VirtioRngDevice {
    pub(super) fn init_legacy(&mut self) -> Result<(), &'static str> {
        self.write8(LEG_STATUS, 0);
        self.write8(LEG_STATUS, VIRTIO_STATUS_ACKNOWLEDGE);
        let cur = self.read8(LEG_STATUS);
        self.write8(LEG_STATUS, cur | VIRTIO_STATUS_DRIVER);
        let _host_features = self.read32(LEG_HOST_FEATURES);
        self.write32(LEG_GUEST_FEATURES, 0);
        let c2 = self.read8(LEG_STATUS);
        self.write8(LEG_STATUS, c2 | VIRTIO_STATUS_FEATURES_OK);
        self.write16(LEG_QUEUE_SEL, 0);
        let qmax = self.read16(LEG_QUEUE_NUM);
        if qmax == 0 {
            return Err("virtio-rng: queue not available");
        }
        let queue_phys = self.queue.desc_table_phys();
        let pfn = (queue_phys >> 12) as u32;
        self.write32(LEG_QUEUE_PFN, pfn);
        match &self.access {
            AccessMode::Io(iobase) => self.queue.set_notify_addr(*iobase + LEG_NOTIFY),
            AccessMode::Mmio(mmio_base) => {
                self.queue.set_notify_mmio(*mmio_base + LEG_NOTIFY as u64)
            }
        }
        let s = self.read8(LEG_STATUS);
        self.write8(LEG_STATUS, s | VIRTIO_STATUS_DRIVER_OK);
        let final_status = self.read8(LEG_STATUS);
        if final_status & VIRTIO_STATUS_DRIVER_OK == 0 {
            return Err("virtio-rng: device rejected DRIVER_OK");
        }
        Ok(())
    }
}
