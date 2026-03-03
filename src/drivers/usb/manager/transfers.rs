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

use core::sync::atomic::Ordering;

use super::super::backend::UsbHostBackend;
use super::super::constants::*;
use super::core::UsbManager;

impl<B: UsbHostBackend> UsbManager<B> {
    pub fn poll_endpoint(&self, device_id: u8, endpoint: u8, buffer: &mut [u8]) -> Result<usize, &'static str> {
        let devices = self.devices.lock();
        let device = devices.iter().find(|d| d.slot_id == device_id)
            .ok_or("Device not found")?;

        let config = device.active_config.as_ref()
            .ok_or("No active configuration")?;

        for interface in &config.interfaces {
            for ep_desc in &interface.endpoints {
                if ep_desc.b_endpoint_address == endpoint {
                    let transfer_type = ep_desc.transfer_type();

                    return match transfer_type {
                        EP_TYPE_ISOCHRONOUS => {
                            Err("Isochronous transfers not supported in polling")
                        }
                        EP_TYPE_BULK => {
                            self.stats.bulk_transfers.fetch_add(1, Ordering::Relaxed);
                            self.backend.bulk_transfer(
                                device.slot_id,
                                endpoint,
                                buffer,
                                DEFAULT_BULK_TIMEOUT_US,
                            ).map_err(|e| {
                                self.stats.bulk_errors.fetch_add(1, Ordering::Relaxed);
                                e
                            })
                        }
                        EP_TYPE_INTERRUPT => {
                            self.stats.int_transfers.fetch_add(1, Ordering::Relaxed);
                            self.backend.interrupt_transfer(
                                device.slot_id,
                                endpoint,
                                buffer,
                                ep_desc.b_interval,
                                DEFAULT_INTERRUPT_TIMEOUT_US,
                            ).map_err(|e| {
                                self.stats.int_errors.fetch_add(1, Ordering::Relaxed);
                                e
                            })
                        }
                        _ => {
                            Err("Control endpoints should use control_transfer")
                        }
                    };
                }
            }
        }

        Err("Endpoint not found in device configuration")
    }

    pub fn bulk_in_transfer(&self, slot_id: u8, endpoint: u8, buffer: &mut [u8]) -> Result<usize, &'static str> {
        self.stats.bulk_transfers.fetch_add(1, Ordering::Relaxed);
        let ep_addr = endpoint | 0x80;
        self.backend.bulk_transfer(slot_id, ep_addr, buffer, DEFAULT_BULK_TIMEOUT_US)
            .map_err(|e| {
                self.stats.bulk_errors.fetch_add(1, Ordering::Relaxed);
                e
            })
    }

    pub fn bulk_out_transfer(&self, slot_id: u8, endpoint: u8, data: &[u8]) -> Result<usize, &'static str> {
        self.stats.bulk_transfers.fetch_add(1, Ordering::Relaxed);
        let ep_addr = endpoint & 0x7F;
        let mut buffer = alloc::vec![0u8; data.len()];
        buffer.copy_from_slice(data);
        self.backend.bulk_transfer(slot_id, ep_addr, &mut buffer, DEFAULT_BULK_TIMEOUT_US)
            .map_err(|e| {
                self.stats.bulk_errors.fetch_add(1, Ordering::Relaxed);
                e
            })
    }

    pub fn control_transfer(
        &self,
        slot_id: u8,
        setup: [u8; 8],
        data_in: Option<&mut [u8]>,
        data_out: Option<&[u8]>,
    ) -> Result<usize, &'static str> {
        self.stats.ctrl_transfers.fetch_add(1, Ordering::Relaxed);
        self.backend.control_transfer(slot_id, setup, data_in, data_out, DEFAULT_CONTROL_TIMEOUT_US)
            .map_err(|e| {
                self.stats.ctrl_errors.fetch_add(1, Ordering::Relaxed);
                e
            })
    }

    pub fn bulk_in(&self, slot_id: u8, endpoint: u8, buffer: &mut [u8]) -> Result<usize, &'static str> {
        self.bulk_in_transfer(slot_id, endpoint, buffer)
    }

    pub fn bulk_out(&self, slot_id: u8, endpoint: u8, data: &[u8]) -> Result<usize, &'static str> {
        self.bulk_out_transfer(slot_id, endpoint, data)
    }

    pub fn control_in(
        &self,
        slot_id: u8,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        buffer: &mut [u8],
    ) -> Result<usize, &'static str> {
        let setup = [
            request_type,
            request,
            (value & 0xFF) as u8,
            (value >> 8) as u8,
            (index & 0xFF) as u8,
            (index >> 8) as u8,
            (buffer.len() & 0xFF) as u8,
            (buffer.len() >> 8) as u8,
        ];
        self.control_transfer(slot_id, setup, Some(buffer), None)
    }

    pub fn control_out(
        &self,
        slot_id: u8,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
    ) -> Result<usize, &'static str> {
        let setup = [
            request_type,
            request,
            (value & 0xFF) as u8,
            (value >> 8) as u8,
            (index & 0xFF) as u8,
            (index >> 8) as u8,
            (data.len() & 0xFF) as u8,
            (data.len() >> 8) as u8,
        ];
        self.control_transfer(slot_id, setup, None, if data.is_empty() { None } else { Some(data) })
    }
}
