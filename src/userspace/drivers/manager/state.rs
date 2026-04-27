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

use super::super::nvme::NvmeDriverService;
use super::super::pci::PciDriverService;
use super::super::virtio::VirtioDriverService;
use spin::Mutex;

pub(super) static DRIVERS: Mutex<Option<DriverState>> = Mutex::new(None);

pub(super) struct DriverState {
    pub(super) pci: PciDriverService,
    pub(super) nvme: NvmeDriverService,
    pub(super) virtio: VirtioDriverService,
}

impl DriverState {
    pub(super) fn new() -> Self {
        Self {
            pci: PciDriverService::new(),
            nvme: NvmeDriverService::new(),
            virtio: VirtioDriverService::new(),
        }
    }
}
