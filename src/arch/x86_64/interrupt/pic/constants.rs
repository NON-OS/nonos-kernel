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

#![allow(dead_code)]

pub(crate) const PIC1_CMD: u16 = 0x20;
pub(crate) const PIC1_DATA: u16 = 0x21;
pub(crate) const PIC2_CMD: u16 = 0xA0;
pub(crate) const PIC2_DATA: u16 = 0xA1;

pub(crate) const ICW1_ICW4: u8 = 0x01;
pub(crate) const ICW1_INIT: u8 = 0x10;
pub(crate) const ICW4_8086: u8 = 0x01;
pub(crate) const ICW4_AEOI: u8 = 0x02;

pub(crate) const OCW2_EOI: u8 = 0x20;
pub(crate) const OCW3_READ_IRR: u8 = 0x0A;
pub(crate) const OCW3_READ_ISR: u8 = 0x0B;

pub(crate) const IMCR_INDEX: u16 = 0x22;
pub(crate) const IMCR_DATA: u16 = 0x23;
pub(crate) const IMCR_SEL: u8 = 0x70;
pub(crate) const IMCR_ROUTE_APIC: u8 = 0x01;

pub const MAX_IRQ: u8 = 15;
pub const SPURIOUS_IRQ_MASTER: u8 = 7;
pub const SPURIOUS_IRQ_SLAVE: u8 = 15;
pub const CASCADE_IRQ: u8 = 2;
