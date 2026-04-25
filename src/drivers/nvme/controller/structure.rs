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

extern crate alloc;

use super::super::namespace::NamespaceManager;
use super::super::queue::{AdminQueue, IoQueue};
use super::super::security::SecurityContext;
use super::super::stats::NvmeStats;
use super::super::types::{ControllerCapabilities, ControllerIdentity, ControllerVersion};
use crate::drivers::pci::PciDevice;
use alloc::vec::Vec;
use spin::Mutex;

pub struct NvmeController {
    pub(super) pci: PciDevice,
    pub(super) mmio_base: usize,
    pub(super) doorbell_stride: u32,
    pub(super) capabilities: ControllerCapabilities,
    pub(super) version: ControllerVersion,
    pub(super) identity: Option<ControllerIdentity>,
    pub(super) admin_queue: Mutex<AdminQueue>,
    pub(super) io_queues: Mutex<Vec<IoQueue>>,
    pub(super) namespaces: Mutex<NamespaceManager>,
    pub(super) stats: NvmeStats,
    pub(super) security: SecurityContext,
    pub(super) initialized: bool,
    pub(super) cpu_queue_map: Mutex<Vec<usize>>,
}

unsafe impl Send for NvmeController {}
unsafe impl Sync for NvmeController {}
