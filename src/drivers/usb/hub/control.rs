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

use super::constants::*;
use super::types::{HubDescriptor, PortStatus};
use crate::drivers::usb::constants::*;
use crate::drivers::usb::error::UsbError;

pub fn get_hub_descriptor(slot_id: u8) -> Result<HubDescriptor, UsbError> {
    let mut buf = [0u8; 16];
    let setup = [DIR_IN | TYPE_CLASS | RT_DEV, HUB_REQ_GET_DESCRIPTOR, DT_HUB, 0, 0, 0, 16, 0];
    let n = do_control(slot_id, setup, Some(&mut buf))?;
    if n < 7 {
        return Err(UsbError::InvalidDescriptor);
    }
    Ok(HubDescriptor {
        length: buf[0],
        desc_type: buf[1],
        num_ports: buf[2],
        characteristics: u16::from_le_bytes([buf[3], buf[4]]),
        power_on_delay: buf[5],
        hub_ctrl_current: buf[6],
    })
}

pub fn get_port_status(slot_id: u8, port: u8) -> Result<PortStatus, UsbError> {
    let mut buf = [0u8; 4];
    let setup = [DIR_IN | TYPE_CLASS | RT_OTHER, HUB_REQ_GET_STATUS, 0, 0, port, 0, 4, 0];
    do_control(slot_id, setup, Some(&mut buf))?;
    Ok(PortStatus::from_bytes(
        u16::from_le_bytes([buf[0], buf[1]]),
        u16::from_le_bytes([buf[2], buf[3]]),
    ))
}

pub fn set_port_feature(slot_id: u8, port: u8, feature: u16) -> Result<(), UsbError> {
    let setup = [
        DIR_OUT | TYPE_CLASS | RT_OTHER,
        HUB_REQ_SET_FEATURE,
        feature as u8,
        (feature >> 8) as u8,
        port,
        0,
        0,
        0,
    ];
    do_control(slot_id, setup, None)?;
    Ok(())
}

pub fn clear_port_feature(slot_id: u8, port: u8, feature: u16) -> Result<(), UsbError> {
    let setup = [
        DIR_OUT | TYPE_CLASS | RT_OTHER,
        HUB_REQ_CLEAR_FEATURE,
        feature as u8,
        (feature >> 8) as u8,
        port,
        0,
        0,
        0,
    ];
    do_control(slot_id, setup, None)?;
    Ok(())
}

pub fn power_on_port(slot_id: u8, port: u8) -> Result<(), UsbError> {
    set_port_feature(slot_id, port, FEAT_PORT_POWER)
}

pub fn reset_port(slot_id: u8, port: u8) -> Result<(), UsbError> {
    set_port_feature(slot_id, port, FEAT_PORT_RESET)?;
    crate::time::delay_ms(HUB_RESET_MS as u64);
    Ok(())
}

pub fn enable_port(slot_id: u8, port: u8) -> Result<(), UsbError> {
    set_port_feature(slot_id, port, FEAT_PORT_ENABLE)
}
pub fn disable_port(slot_id: u8, port: u8) -> Result<(), UsbError> {
    clear_port_feature(slot_id, port, FEAT_PORT_ENABLE)
}
pub fn clear_connection_change(slot_id: u8, port: u8) -> Result<(), UsbError> {
    clear_port_feature(slot_id, port, FEAT_C_PORT_CONNECTION)
}

fn do_control(slot_id: u8, setup: [u8; 8], data: Option<&mut [u8]>) -> Result<usize, UsbError> {
    crate::drivers::xhci::control_transfer(slot_id, setup, data, DEFAULT_CONTROL_TIMEOUT_US)
        .map_err(|_| UsbError::TransferFailed)
}
