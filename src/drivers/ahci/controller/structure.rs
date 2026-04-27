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

use super::super::dma::PortDma;
use super::super::types::AhciDevice;
use super::helpers::RegisterAccess;
use crate::crypto::aes::Aes256;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};
use spin::{Mutex, RwLock};

pub struct AhciController {
    pub(super) base_addr: usize,
    pub(super) ports: RwLock<BTreeMap<u32, AhciDevice>>,
    pub(super) port_dma: Mutex<BTreeMap<u32, PortDma>>,
    pub(super) read_ops: AtomicU64,
    pub(super) write_ops: AtomicU64,
    pub(super) trim_ops: AtomicU64,
    pub(super) errors: AtomicU64,
    pub(super) bytes_read: AtomicU64,
    pub(super) bytes_written: AtomicU64,
    pub(super) port_resets: AtomicU64,
    pub(super) validation_failures: AtomicU64,
    pub(super) encryption_enabled: AtomicBool,
    pub(super) aes_cipher: Mutex<Option<Aes256>>,
    pub(super) encryption_iv: [u8; 16],
    pub(super) command_timeout: AtomicU32,
}

impl RegisterAccess for AhciController {
    fn base_addr(&self) -> usize {
        self.base_addr
    }
}
