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

//! Broker class id for xHCI controllers. The kernel-side
//! `classify_pci` maps PCI class 0x0C / subclass 0x03 / prog-if
//! 0x30 to this id; older UHCI/OHCI/EHCI prog-ifs land on the
//! generic USB_HOST id (0x0070) which this capsule does not
//! match on.

pub const CLASS_USB_HOST_XHCI: u32 = 0x0071;
