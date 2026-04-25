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

use core::sync::atomic::{AtomicU64, AtomicU8};

pub(crate) static XHCI_BAR: AtomicU64 = AtomicU64::new(0);
pub(crate) static XHCI_OP: AtomicU64 = AtomicU64::new(0);
pub(crate) static XHCI_DB: AtomicU64 = AtomicU64::new(0);
pub(crate) static XHCI_RT: AtomicU64 = AtomicU64::new(0);
pub(crate) static MAX_PORTS: AtomicU8 = AtomicU8::new(0);

pub(crate) static SLOT_ID: AtomicU8 = AtomicU8::new(0);
pub(crate) static DEV_SPEED: AtomicU8 = AtomicU8::new(0);
pub(crate) static PORT_ID: AtomicU8 = AtomicU8::new(0);
pub(crate) static HID_EP_ADDR: AtomicU8 = AtomicU8::new(0);
pub(crate) static HID_EP_DCI: AtomicU8 = AtomicU8::new(0);
pub(crate) static HID_INTERVAL: AtomicU8 = AtomicU8::new(8);
pub(crate) static MAX_PACKET: AtomicU8 = AtomicU8::new(8);
