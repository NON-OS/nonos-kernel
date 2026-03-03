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

use super::super::constants::*;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EndpointDescriptor {
    pub b_length: u8,
    pub b_descriptor_type: u8,
    pub b_endpoint_address: u8,
    pub bm_attributes: u8,
    pub w_max_packet_size: u16,
    pub b_interval: u8,
}

impl EndpointDescriptor {
    pub fn endpoint_number(&self) -> u8 {
        self.b_endpoint_address & 0x0F
    }

    pub fn is_in(&self) -> bool {
        (self.b_endpoint_address & 0x80) != 0
    }

    pub fn is_out(&self) -> bool {
        (self.b_endpoint_address & 0x80) == 0
    }

    pub fn transfer_type(&self) -> u8 {
        self.bm_attributes & EP_TRANSFER_TYPE_MASK
    }

    pub fn is_control(&self) -> bool {
        self.transfer_type() == EP_TYPE_CONTROL
    }

    pub fn is_isochronous(&self) -> bool {
        self.transfer_type() == EP_TYPE_ISOCHRONOUS
    }

    pub fn is_bulk(&self) -> bool {
        self.transfer_type() == EP_TYPE_BULK
    }

    pub fn is_interrupt(&self) -> bool {
        self.transfer_type() == EP_TYPE_INTERRUPT
    }

    pub fn max_packet_size(&self) -> u16 {
        u16::from_le(self.w_max_packet_size) & 0x07FF
    }

    pub fn transfer_type_name(&self) -> &'static str {
        match self.transfer_type() {
            EP_TYPE_CONTROL => "Control",
            EP_TYPE_ISOCHRONOUS => "Isochronous",
            EP_TYPE_BULK => "Bulk",
            EP_TYPE_INTERRUPT => "Interrupt",
            _ => "Unknown",
        }
    }
}
