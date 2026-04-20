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

pub(crate) const XHCI_CAP_CAPLENGTH: u64 = 0x00;
pub(crate) const XHCI_CAP_HCSPARAMS1: u64 = 0x04;
pub(crate) const XHCI_CAP_HCSPARAMS2: u64 = 0x08;
pub(crate) const XHCI_CAP_DBOFF: u64 = 0x14;
pub(crate) const XHCI_CAP_RTSOFF: u64 = 0x18;
pub(crate) const XHCI_CAP_HCCPARAMS1: u64 = 0x10;

pub(crate) const XHCI_OP_USBCMD: u64 = 0x00;
pub(crate) const XHCI_OP_USBSTS: u64 = 0x04;
pub(crate) const XHCI_OP_CRCR: u64 = 0x18;
pub(crate) const XHCI_OP_DCBAAP: u64 = 0x30;
pub(crate) const XHCI_OP_CONFIG: u64 = 0x38;
pub(crate) const XHCI_OP_PORTSC_BASE: u64 = 0x400;

pub(crate) const XHCI_RT_ERSTSZ: u64 = 0x28;
pub(crate) const XHCI_RT_ERSTBA: u64 = 0x30;
pub(crate) const XHCI_RT_ERDP: u64 = 0x38;

pub(crate) const USBCMD_RS: u32 = 1 << 0;
pub(crate) const USBCMD_HCRST: u32 = 1 << 1;
pub(crate) const USBCMD_INTE: u32 = 1 << 2;

pub(crate) const USBSTS_HCH: u32 = 1 << 0;
pub(crate) const USBSTS_CNR: u32 = 1 << 11;

pub(crate) const PORTSC_CCS: u32 = 1 << 0;
pub(crate) const PORTSC_PED: u32 = 1 << 1;
pub(crate) const PORTSC_PR: u32 = 1 << 4;
pub(crate) const PORTSC_PLS_MASK: u32 = 0xF << 5;
pub(crate) const PORTSC_PP: u32 = 1 << 9;
pub(crate) const PORTSC_CSC: u32 = 1 << 17;
pub(crate) const PORTSC_PRC: u32 = 1 << 21;
pub(crate) const PORTSC_WRC: u32 = 1 << 19;

pub(crate) const TRB_TYPE_ENABLE_SLOT: u32 = 9;
pub(crate) const TRB_TYPE_ADDRESS_DEVICE: u32 = 11;
pub(crate) const TRB_TYPE_CONFIGURE_ENDPOINT: u32 = 12;

pub(crate) const TRB_CYCLE: u32 = 1 << 0;
