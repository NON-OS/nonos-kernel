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

use core::sync::atomic::{AtomicBool, AtomicU64};
use spin::Mutex;

use super::super::types::{DomainId, SourceId, MAX_VTD_DOMAINS};

pub(crate) const FIRST_DYNAMIC_DOMAIN_ID: u64 = 1;

pub(crate) struct DomainSlot {
    pub used: bool,
}

pub(crate) struct DeviceBinding {
    pub source: SourceId,
    pub domain: DomainId,
}

pub(crate) struct VtdState {
    pub domains: [DomainSlot; MAX_VTD_DOMAINS],
    pub bindings: heapless::Vec<DeviceBinding, { super::super::types::MAX_VTD_DEVICES }>,
}

impl VtdState {
    const fn new() -> Self {
        const SLOT: DomainSlot = DomainSlot { used: false };
        Self { domains: [SLOT; MAX_VTD_DOMAINS], bindings: heapless::Vec::new() }
    }
}

pub(crate) static DMAR_PRESENT: AtomicBool = AtomicBool::new(false);
pub(crate) static NEXT_DOMAIN_ID: AtomicU64 = AtomicU64::new(FIRST_DYNAMIC_DOMAIN_ID);
pub(crate) static STATE: Mutex<VtdState> = Mutex::new(VtdState::new());
