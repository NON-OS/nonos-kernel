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

use core::sync::atomic::AtomicU64;

pub(super) static TOTAL_DEVICES: AtomicU64 = AtomicU64::new(0);
pub(super) static BRIDGE_DEVICES: AtomicU64 = AtomicU64::new(0);
pub(super) static MSI_CAPABLE_DEVICES: AtomicU64 = AtomicU64::new(0);
pub(super) static MSIX_CAPABLE_DEVICES: AtomicU64 = AtomicU64::new(0);
pub(super) static PCIE_DEVICES: AtomicU64 = AtomicU64::new(0);
pub(super) static DMA_CAPABLE_DEVICES: AtomicU64 = AtomicU64::new(0);
pub(super) static ENUMERATION_COUNT: AtomicU64 = AtomicU64::new(0);
pub(super) static ENUMERATION_TIME_US: AtomicU64 = AtomicU64::new(0);
pub(super) static CONFIG_READS: AtomicU64 = AtomicU64::new(0);
pub(super) static CONFIG_WRITES: AtomicU64 = AtomicU64::new(0);
pub(super) static CONFIG_ERRORS: AtomicU64 = AtomicU64::new(0);
pub(super) static INTERRUPTS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub(super) static MSI_INTERRUPTS: AtomicU64 = AtomicU64::new(0);
pub(super) static LEGACY_INTERRUPTS: AtomicU64 = AtomicU64::new(0);
pub(super) static HOTPLUG_EVENTS: AtomicU64 = AtomicU64::new(0);
pub(super) static POWER_STATE_CHANGES: AtomicU64 = AtomicU64::new(0);
pub(super) static LINK_STATE_CHANGES: AtomicU64 = AtomicU64::new(0);
pub(super) static ERROR_EVENTS: AtomicU64 = AtomicU64::new(0);
