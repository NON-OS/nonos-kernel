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

use super::super::constants::ETHERNET_HEADER_SIZE;
use super::super::error::VirtioNetError;
use super::mac::validate_source_mac;
use super::types::EtherType;

pub fn validate_ethernet_frame(frame: &[u8]) -> Result<(), VirtioNetError> {
    if frame.len() < ETHERNET_HEADER_SIZE {
        return Err(VirtioNetError::MalformedPacket);
    }
    let src_mac: [u8; 6] = [frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]];
    validate_source_mac(&src_mac)?;
    Ok(())
}

pub fn validate_ethernet_frame_extended(frame: &[u8]) -> Result<EtherType, VirtioNetError> {
    validate_ethernet_frame(frame)?;
    let ethertype = ((frame[12] as u16) << 8) | (frame[13] as u16);
    match ethertype {
        0x0800 => Ok(EtherType::Ipv4),
        0x0806 => Ok(EtherType::Arp),
        0x86DD => Ok(EtherType::Ipv6),
        0x8100 => Ok(EtherType::Vlan),
        0x88A8 => Ok(EtherType::QinQ),
        _ if ethertype >= 0x0600 => Ok(EtherType::Other(ethertype)),
        _ => Ok(EtherType::Llc(ethertype)),
    }
}
