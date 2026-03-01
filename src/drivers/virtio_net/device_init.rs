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

use alloc::{sync::Arc, vec::Vec};
use core::ptr;
use spin::Mutex;

use crate::drivers::pci::PciBar;

use super::buffer::PacketBuffer;
use super::constants::*;
use super::device::VirtioNetDevice;
use super::modern_regs::VirtioModernRegs;

impl VirtioNetDevice {
    pub(super) fn init_modern(regs: &VirtioModernRegs) -> Result<([u8; 6], u32), &'static str> {
        // SAFETY: regs.common is valid MMIO memory from PCI capability parsing
        unsafe {
            let common_ptr = regs.common.as_ptr();

            ptr::write_unaligned(
                ptr::addr_of_mut!((*common_ptr).device_status),
                VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
            );

            ptr::write_unaligned(ptr::addr_of_mut!((*common_ptr).device_feature_select), 0);
            let devf = ptr::read_unaligned(ptr::addr_of!((*common_ptr).device_feature));

            let supported = (1 << VIRTIO_NET_F_MAC)
                | (1 << VIRTIO_NET_F_STATUS)
                | (1 << VIRTIO_NET_F_CTRL_VQ);

            ptr::write_unaligned(ptr::addr_of_mut!((*common_ptr).driver_feature_select), 0);
            ptr::write_unaligned(
                ptr::addr_of_mut!((*common_ptr).driver_feature),
                devf & supported,
            );

            let s0 = ptr::read_unaligned(ptr::addr_of!((*common_ptr).device_status));
            ptr::write_unaligned(
                ptr::addr_of_mut!((*common_ptr).device_status),
                s0 | VIRTIO_STATUS_FEATURES_OK,
            );

            let s1 = ptr::read_unaligned(ptr::addr_of!((*common_ptr).device_status));
            if (s1 & VIRTIO_STATUS_FEATURES_OK) == 0 {
                return Err("virtio-net: FEATURES_OK rejected");
            }

            let mac = regs.read_mac_address();

            Ok((mac, devf & supported))
        }
    }

    pub(super) fn init_legacy(legacy_bar: &Option<PciBar>) -> Result<([u8; 6], u32), &'static str> {
        let bar = legacy_bar.as_ref().ok_or("virtio-net: missing legacy BAR")?;
        let base = match bar {
            PciBar::Memory { address, .. } => address.as_u64() as usize,
            _ => return Err("virtio-net: legacy needs MMIO BAR"),
        };

        // SAFETY: base points to valid MMIO memory from BAR
        unsafe {
            ptr::write_volatile((base + LEG_STATUS) as *mut u8, 0);
            ptr::write_volatile((base + LEG_STATUS) as *mut u8, VIRTIO_STATUS_ACKNOWLEDGE);

            let cur = ptr::read_volatile((base + LEG_STATUS) as *const u8);
            ptr::write_volatile((base + LEG_STATUS) as *mut u8, cur | VIRTIO_STATUS_DRIVER);

            let devf = ptr::read_volatile((base + LEG_HOST_FEATURES) as *const u32);
            let supported = (1 << VIRTIO_NET_F_MAC) | (1 << VIRTIO_NET_F_STATUS);
            ptr::write_volatile((base + LEG_GUEST_FEATURES) as *mut u32, devf & supported);

            let c2 = ptr::read_volatile((base + LEG_STATUS) as *const u8);
            ptr::write_volatile((base + LEG_STATUS) as *mut u8, c2 | VIRTIO_STATUS_FEATURES_OK);

            let mut mac = [0u8; 6];
            for i in 0..6 {
                mac[i] = ptr::read_volatile((base + LEG_MAC + i) as *const u8);
            }

            Ok((mac, devf & supported))
        }
    }

    pub(super) fn setup_queues_modern(&mut self) -> Result<(), &'static str> {
        let regs = self.modern.as_ref().ok_or("virtio-net: modern interface not available")?;

        // SAFETY: regs.common is valid MMIO memory
        unsafe {
            let common_ptr = regs.common.as_ptr();

            for qidx in [Q_RX, Q_TX] {
                ptr::write_unaligned(ptr::addr_of_mut!((*common_ptr).queue_select), qidx);

                let qmax = ptr::read_unaligned(ptr::addr_of!((*common_ptr).queue_size));
                if qmax == 0 {
                    return Err("virtio-net: queue not available");
                }

                let qsize = core::cmp::min(DEFAULT_QUEUE_SIZE, qmax);
                ptr::write_unaligned(ptr::addr_of_mut!((*common_ptr).queue_size), qsize);

                let (desc, avail, used) = match qidx {
                    Q_RX => {
                        let q = self.rx_queue.get_mut();
                        (
                            q.desc_table_phys.as_u64(),
                            q.avail_ring_phys.as_u64(),
                            q.used_ring_phys.as_u64(),
                        )
                    }
                    Q_TX => {
                        let q = self.tx_queue.get_mut();
                        (
                            q.desc_table_phys.as_u64(),
                            q.avail_ring_phys.as_u64(),
                            q.used_ring_phys.as_u64(),
                        )
                    }
                    _ => unreachable!(),
                };

                ptr::write_unaligned(ptr::addr_of_mut!((*common_ptr).queue_desc), desc);
                ptr::write_unaligned(ptr::addr_of_mut!((*common_ptr).queue_avail), avail);
                ptr::write_unaligned(ptr::addr_of_mut!((*common_ptr).queue_used), used);

                ptr::write_unaligned(ptr::addr_of_mut!((*common_ptr).queue_enable), 1);

                let noff = ptr::read_unaligned(ptr::addr_of!((*common_ptr).queue_notify_off));
                let naddr = regs.queue_notify_addr(noff);

                match qidx {
                    Q_RX => self.rx_queue.get_mut().set_notify_addr(naddr),
                    Q_TX => self.tx_queue.get_mut().set_notify_addr(naddr),
                    _ => {}
                }
            }
        }

        Ok(())
    }

    pub(super) fn setup_queues_legacy(&mut self) -> Result<(), &'static str> {
        let bar = self.legacy_bar.as_ref().ok_or("virtio-net: legacy BAR missing")?;
        let base = match bar {
            PciBar::Memory { address, .. } => address.as_u64() as usize,
            _ => return Err("virtio-net: legacy needs MMIO BAR"),
        };

        // SAFETY: base points to valid MMIO memory from BAR
        unsafe {
            for qidx in [Q_RX, Q_TX] {
                ptr::write_volatile((base + LEG_QUEUE_SEL) as *mut u16, qidx);

                let qmax = ptr::read_volatile((base + LEG_QUEUE_NUM) as *const u16);
                if qmax == 0 {
                    return Err("virtio-net: legacy queue not available");
                }

                let queue_phys = match qidx {
                    Q_RX => self.rx_queue.get_mut().desc_table_phys.as_u64(),
                    Q_TX => self.tx_queue.get_mut().desc_table_phys.as_u64(),
                    _ => unreachable!(),
                };

                let pfn = (queue_phys >> 12) as u32;
                ptr::write_volatile((base + LEG_QUEUE_PFN) as *mut u32, pfn);

                let notify_addr = (base + LEG_NOTIFY) as usize;
                match qidx {
                    Q_RX => self.rx_queue.get_mut().set_notify_addr(notify_addr),
                    Q_TX => self.tx_queue.get_mut().set_notify_addr(notify_addr),
                    _ => {}
                }
            }
        }

        Ok(())
    }

    pub(super) fn allocate_buffers(&mut self) -> Result<(), &'static str> {
        {
            let mut rx = self.rx_buffers.lock();
            for _ in 0..DEFAULT_RX_BUFFER_COUNT {
                rx.push(Arc::new(Mutex::new(PacketBuffer::new(RX_BUFFER_SIZE)?)));
            }
        }

        {
            let mut tx = self.tx_buffers.lock();
            for _ in 0..DEFAULT_TX_BUFFER_COUNT {
                tx.push(Arc::new(Mutex::new(PacketBuffer::new(TX_BUFFER_SIZE)?)));
            }
        }

        Ok(())
    }

    pub(super) fn set_status_driver_ok(&mut self) {
        if let Some(ref regs) = self.modern {
            // SAFETY: regs.common is valid MMIO memory
            unsafe {
                let common_ptr = regs.common.as_ptr();
                let s = ptr::read_unaligned(&(*common_ptr).device_status);
                ptr::write_unaligned(
                    &mut (*common_ptr).device_status,
                    s | VIRTIO_STATUS_DRIVER_OK,
                );
            }
        } else if let Some(PciBar::Memory { address, .. }) = &self.legacy_bar {
            let base = address.as_u64() as usize;
            // SAFETY: base points to valid MMIO memory from BAR
            unsafe {
                let s = ptr::read_volatile((base + LEG_STATUS) as *const u8);
                ptr::write_volatile((base + LEG_STATUS) as *mut u8, s | VIRTIO_STATUS_DRIVER_OK);
            }
        }
    }

    pub fn deinit(&mut self) {
        if let Some(ref regs) = self.modern {
            // SAFETY: regs.common is valid MMIO memory
            unsafe {
                let common_ptr = regs.common.as_ptr();
                ptr::write_unaligned(ptr::addr_of_mut!((*common_ptr).device_status), 0);
            }
        } else if let Some(PciBar::Memory { address, .. }) = &self.legacy_bar {
            let base = address.as_u64() as usize;
            // SAFETY: base points to valid MMIO memory from BAR
            unsafe {
                ptr::write_volatile((base + LEG_STATUS) as *mut u8, 0);
            }
        }

        self.rx_buffers.lock().clear();
        self.tx_buffers.lock().clear();

        crate::log::info!("virtio-net: device deinitialized");
    }
}
