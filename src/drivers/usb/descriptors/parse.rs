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

extern crate alloc;

use alloc::vec::Vec;

use super::super::constants::*;
use super::config::ConfigDescriptorHeader;
use super::endpoint::EndpointDescriptor;
use super::interface::{InterfaceDescriptor, UsbInterfaceInfo};

pub fn parse_interfaces(cfg: &[u8]) -> Result<Vec<UsbInterfaceInfo>, &'static str> {
    let mut i = 0usize;
    let total = cfg.len();

    if total < core::mem::size_of::<ConfigDescriptorHeader>() {
        return Err("Configuration descriptor too small");
    }
    i += core::mem::size_of::<ConfigDescriptorHeader>();

    let mut out = Vec::new();
    let mut cur_iface: Option<UsbInterfaceInfo> = None;

    while i + 1 < total {
        let len = cfg[i] as usize;
        if len == 0 || i + len > total {
            break;
        }
        let dtype = cfg[i + 1];

        match dtype {
            DT_INTERFACE => {
                if let Some(iface) = cur_iface.take() {
                    out.push(iface);
                }

                if i + core::mem::size_of::<InterfaceDescriptor>() <= total {
                    // SAFETY: bounds verified, using read_unaligned for packed struct.
                    let desc: InterfaceDescriptor =
                        unsafe { core::ptr::read_unaligned(cfg[i..].as_ptr() as *const _) };
                    cur_iface = Some(UsbInterfaceInfo {
                        iface: desc,
                        endpoints: Vec::new(),
                    });
                }
            }
            DT_ENDPOINT => {
                if i + core::mem::size_of::<EndpointDescriptor>() <= total {
                    // SAFETY: bounds verified, using read_unaligned for packed struct.
                    let ep: EndpointDescriptor =
                        unsafe { core::ptr::read_unaligned(cfg[i..].as_ptr() as *const _) };
                    if let Some(ref mut iface) = cur_iface {
                        iface.endpoints.push(ep);
                    }
                }
            }
            _ => {}
        }
        i += len;
    }

    if let Some(iface) = cur_iface.take() {
        out.push(iface);
    }

    Ok(out)
}
