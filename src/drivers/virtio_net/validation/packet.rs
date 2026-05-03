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

use super::super::constants::{MAX_ETHERNET_FRAME, MIN_ETHERNET_FRAME};
use super::super::error::VirtioNetError;
use super::super::header::VirtioNetHeader;
use super::dma::validate_dma_address;
use super::ethernet::validate_ethernet_frame;
use crate::memory::addr::PhysAddr;
use core::mem;

pub fn validate_packet_size(size: usize, include_header: bool) -> Result<(), VirtioNetError> {
    let header_size = if include_header { mem::size_of::<VirtioNetHeader>() } else { 0 };
    if size < header_size {
        return Err(VirtioNetError::PacketTooSmall);
    }
    let payload_size = size - header_size;
    if payload_size < MIN_ETHERNET_FRAME {
        return Err(VirtioNetError::PacketTooSmall);
    }
    if payload_size > MAX_ETHERNET_FRAME {
        return Err(VirtioNetError::PacketExceedsMtu);
    }
    Ok(())
}

pub fn validate_rx_packet(data: &[u8], reported_len: u32) -> Result<(), VirtioNetError> {
    let header_size = mem::size_of::<VirtioNetHeader>();
    if reported_len as usize > data.len() {
        return Err(VirtioNetError::MalformedPacket);
    }
    let min_size = header_size + MIN_ETHERNET_FRAME;
    if (reported_len as usize) < min_size {
        return Err(VirtioNetError::PacketTooSmall);
    }
    let max_size = header_size + MAX_ETHERNET_FRAME;
    if (reported_len as usize) > max_size {
        return Err(VirtioNetError::PacketExceedsMtu);
    }
    if data.len() >= header_size {
        let hdr = unsafe { &*(data.as_ptr() as *const VirtioNetHeader) };
        hdr.validate()?;
        let frame = &data[header_size..reported_len as usize];
        validate_ethernet_frame(frame)?;
    }
    Ok(())
}

pub fn validate_tx_buffer(
    payload: &[u8],
    dma_addr: PhysAddr,
    buffer_capacity: usize,
) -> Result<(), VirtioNetError> {
    validate_packet_size(payload.len(), false)?;
    validate_ethernet_frame(payload)?;
    let total_size = mem::size_of::<VirtioNetHeader>() + payload.len();
    if total_size > buffer_capacity {
        return Err(VirtioNetError::BufferTooSmall);
    }
    validate_dma_address(dma_addr, total_size)?;
    Ok(())
}
