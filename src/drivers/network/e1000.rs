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

//! Intel e1000/e1000e NIC driver for QEMU virtual NIC.
//! Supports Intel 82574L (device ID 0x10D3) emulated by QEMU.

extern crate alloc;

use alloc::vec::Vec;
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;
use crate::bus::pci::{find_device, enable_bus_master, enable_memory_space, PciDevice};
use crate::network::stack::SmolDevice;
use crate::sys::serial;

const REG_CTRL: u32 = 0x0000;      // Device Control
const REG_ICR: u32 = 0x00C0;       // Interrupt Cause Read
const REG_IMC: u32 = 0x00D8;       // Interrupt Mask Clear
const REG_RCTL: u32 = 0x0100;      // Receive Control
const REG_TCTL: u32 = 0x0400;      // Transmit Control
const REG_RDBAL: u32 = 0x2800;     // RX Descriptor Base Low
const REG_RDBAH: u32 = 0x2804;     // RX Descriptor Base High
const REG_RDLEN: u32 = 0x2808;     // RX Descriptor Length
const REG_RDH: u32 = 0x2810;       // RX Descriptor Head
const REG_RDT: u32 = 0x2818;       // RX Descriptor Tail
const REG_TDBAL: u32 = 0x3800;     // TX Descriptor Base Low
const REG_TDBAH: u32 = 0x3804;     // TX Descriptor Base High
const REG_TDLEN: u32 = 0x3808;     // TX Descriptor Length
const REG_TDH: u32 = 0x3810;       // TX Descriptor Head
const REG_TDT: u32 = 0x3818;       // TX Descriptor Tail
const REG_RAL0: u32 = 0x5400;      // Receive Address Low
const REG_RAH0: u32 = 0x5404;      // Receive Address High

const CTRL_SLU: u32 = 1 << 6;      // Set Link Up
const CTRL_RST: u32 = 1 << 26;     // Device Reset

const RCTL_EN: u32 = 1 << 1;       // Receiver Enable
const RCTL_BAM: u32 = 1 << 15;     // Broadcast Accept Mode
const RCTL_BSIZE_2048: u32 = 0 << 16;
const RCTL_SECRC: u32 = 1 << 26;   // Strip Ethernet CRC

const TCTL_EN: u32 = 1 << 1;       // Transmitter Enable
const TCTL_PSP: u32 = 1 << 3;      // Pad Short Packets
const TCTL_CT_SHIFT: u32 = 4;      // Collision Threshold
const TCTL_COLD_SHIFT: u32 = 12;   // Collision Distance

const DESC_DD: u8 = 1 << 0;        // Descriptor Done

const DESC_CMD_EOP: u8 = 1 << 0;   // End of Packet
const DESC_CMD_IFCS: u8 = 1 << 1;  // Insert FCS
const DESC_CMD_RS: u8 = 1 << 3;    // Report Status

const NUM_RX_DESC: usize = 32;
const NUM_TX_DESC: usize = 32;
const RX_BUFFER_SIZE: usize = 2048;

static mut STATIC_RX_DESCS: [RxDesc; NUM_RX_DESC] = [RxDesc::new_static(); NUM_RX_DESC];
static mut STATIC_TX_DESCS: [TxDesc; NUM_TX_DESC] = [TxDesc::new_static(); NUM_TX_DESC];
static mut STATIC_RX_BUFS: [[u8; RX_BUFFER_SIZE]; NUM_RX_DESC] = [[0u8; RX_BUFFER_SIZE]; NUM_RX_DESC];
static mut STATIC_TX_BUFS: [[u8; RX_BUFFER_SIZE]; NUM_TX_DESC] = [[0u8; RX_BUFFER_SIZE]; NUM_TX_DESC];

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct RxDesc {
    addr: u64,
    length: u16,
    checksum: u16,
    status: u8,
    errors: u8,
    special: u16,
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct TxDesc {
    addr: u64,
    length: u16,
    cso: u8,
    cmd: u8,
    status: u8,
    css: u8,
    special: u16,
}

impl RxDesc {
    const fn new_static() -> Self {
        Self {
            addr: 0,
            length: 0,
            checksum: 0,
            status: 0,
            errors: 0,
            special: 0,
        }
    }
}

impl TxDesc {
    const fn new_static() -> Self {
        Self {
            addr: 0,
            length: 0,
            cso: 0,
            cmd: 0,
            status: 0,
            css: 0,
            special: 0,
        }
    }
}

pub struct E1000 {
    mmio_base: u64,
    mac: [u8; 6],
    rx_cur: AtomicU32,
    tx_cur: AtomicU32,
    initialized: AtomicBool,
    rx_queue: Mutex<Vec<Vec<u8>>>,
}

impl E1000 {
    pub fn new() -> Option<Self> {
        let dev = find_e1000_device()?;

        serial::print(b"[E1000] Found at ");
        serial::print_dec(dev.bus as u64);
        serial::print(b":");
        serial::print_dec(dev.device as u64);
        serial::println(b"");

        enable_bus_master(dev.bus, dev.device, dev.function);
        enable_memory_space(dev.bus, dev.device, dev.function);

        let bar0 = dev.bar0 as u64;
        if bar0 == 0 {
            serial::println(b"[E1000] BAR0 is zero!");
            return None;
        }

        let mmio_base = bar0 & !0xF; // Mask off lower bits
        serial::print(b"[E1000] MMIO base: 0x");
        serial::print_hex(mmio_base);
        serial::println(b"");

        serial::println(b"[E1000] Using static buffers...");

        Some(Self {
            mmio_base,
            mac: [0; 6],
            rx_cur: AtomicU32::new(0),
            tx_cur: AtomicU32::new(0),
            initialized: AtomicBool::new(false),
            rx_queue: Mutex::new(Vec::new()),
        })
    }

    fn read_reg(&self, reg: u32) -> u32 {
        unsafe {
            core::ptr::read_volatile((self.mmio_base + reg as u64) as *const u32)
        }
    }

    fn write_reg(&self, reg: u32, val: u32) {
        unsafe {
            core::ptr::write_volatile((self.mmio_base + reg as u64) as *mut u32, val);
        }
    }

    fn read_mac(&mut self) {
        let ral = self.read_reg(REG_RAL0);
        let rah = self.read_reg(REG_RAH0);

        if ral != 0 || (rah & 0xFFFF) != 0 {
            self.mac[0] = (ral >> 0) as u8;
            self.mac[1] = (ral >> 8) as u8;
            self.mac[2] = (ral >> 16) as u8;
            self.mac[3] = (ral >> 24) as u8;
            self.mac[4] = (rah >> 0) as u8;
            self.mac[5] = (rah >> 8) as u8;
        } else {
            self.mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        }

        serial::print(b"[E1000] MAC: ");
        for (i, &b) in self.mac.iter().enumerate() {
            if i > 0 { serial::print(b":"); }
            serial::print_hex(b as u64);
        }
        serial::println(b"");
    }

    pub fn init(&mut self) -> Result<(), &'static str> {
        serial::println(b"[E1000] Initializing...");

        self.write_reg(REG_CTRL, CTRL_RST);
        for _ in 0..10000 { core::hint::spin_loop(); }

        while self.read_reg(REG_CTRL) & CTRL_RST != 0 {
            core::hint::spin_loop();
        }

        self.write_reg(REG_IMC, 0xFFFFFFFF);
        self.read_reg(REG_ICR); // Clear pending interrupts

        self.read_mac();

        let ctrl = self.read_reg(REG_CTRL);
        self.write_reg(REG_CTRL, ctrl | CTRL_SLU);

        self.init_rx()?;

        self.init_tx()?;

        self.write_reg(REG_RCTL, RCTL_EN | RCTL_BAM | RCTL_BSIZE_2048 | RCTL_SECRC);
        self.write_reg(REG_TCTL, TCTL_EN | TCTL_PSP | (15 << TCTL_CT_SHIFT) | (64 << TCTL_COLD_SHIFT));

        self.initialized.store(true, Ordering::SeqCst);

        serial::println(b"[E1000] Initialized successfully!");
        Ok(())
    }

    fn init_rx(&mut self) -> Result<(), &'static str> {
        // SAFETY: Single-threaded initialization, hardware requires static DMA buffers
        unsafe {
            let rx_bufs = addr_of!(STATIC_RX_BUFS) as *const [[u8; RX_BUFFER_SIZE]; NUM_RX_DESC];
            let rx_descs = addr_of_mut!(STATIC_RX_DESCS) as *mut [RxDesc; NUM_RX_DESC];

            for i in 0..NUM_RX_DESC {
                let buf_addr = (*rx_bufs)[i].as_ptr() as u64;
                (*rx_descs)[i].addr = buf_addr;
                (*rx_descs)[i].status = 0;
            }

            let desc_addr = rx_descs as u64;

            self.write_reg(REG_RDBAL, desc_addr as u32);
            self.write_reg(REG_RDBAH, (desc_addr >> 32) as u32);
            self.write_reg(REG_RDLEN, (NUM_RX_DESC * core::mem::size_of::<RxDesc>()) as u32);
            self.write_reg(REG_RDH, 0);
            self.write_reg(REG_RDT, (NUM_RX_DESC - 1) as u32);
        }

        self.rx_cur.store(0, Ordering::SeqCst);

        serial::println(b"[E1000] RX ring initialized");
        Ok(())
    }

    fn init_tx(&mut self) -> Result<(), &'static str> {
        // SAFETY: Single-threaded initialization, hardware requires static DMA buffers
        unsafe {
            let tx_bufs = addr_of!(STATIC_TX_BUFS) as *const [[u8; RX_BUFFER_SIZE]; NUM_TX_DESC];
            let tx_descs = addr_of_mut!(STATIC_TX_DESCS) as *mut [TxDesc; NUM_TX_DESC];

            for i in 0..NUM_TX_DESC {
                let buf_addr = (*tx_bufs)[i].as_ptr() as u64;
                (*tx_descs)[i].addr = buf_addr;
                (*tx_descs)[i].status = DESC_DD;
                (*tx_descs)[i].cmd = 0;
            }

            let desc_addr = tx_descs as u64;

            self.write_reg(REG_TDBAL, desc_addr as u32);
            self.write_reg(REG_TDBAH, (desc_addr >> 32) as u32);
            self.write_reg(REG_TDLEN, (NUM_TX_DESC * core::mem::size_of::<TxDesc>()) as u32);
            self.write_reg(REG_TDH, 0);
            self.write_reg(REG_TDT, 0);
        }

        self.tx_cur.store(0, Ordering::SeqCst);

        serial::println(b"[E1000] TX ring initialized");
        Ok(())
    }

    pub fn poll_rx(&self) {
        if !self.initialized.load(Ordering::SeqCst) {
            return;
        }

        let mut cur = self.rx_cur.load(Ordering::SeqCst) as usize;

        // SAFETY: Accessing static DMA buffers, single-threaded NIC access via atomic guards
        unsafe {
            let rx_descs = addr_of_mut!(STATIC_RX_DESCS) as *mut [RxDesc; NUM_RX_DESC];
            let rx_bufs = addr_of!(STATIC_RX_BUFS) as *const [[u8; RX_BUFFER_SIZE]; NUM_RX_DESC];

            while ((*rx_descs)[cur].status & DESC_DD) != 0 {
                let length = (*rx_descs)[cur].length as usize;

                if length > 0 && length <= RX_BUFFER_SIZE {
                    let mut packet = Vec::with_capacity(length);
                    packet.extend_from_slice(&(&(*rx_bufs)[cur])[..length]);
                    self.rx_queue.lock().push(packet);
                }

                (*rx_descs)[cur].status = 0;
                self.write_reg(REG_RDT, cur as u32);
                cur = (cur + 1) % NUM_RX_DESC;
            }
        }

        self.rx_cur.store(cur as u32, Ordering::SeqCst);
    }

    pub fn transmit(&self, data: &[u8]) -> Result<(), ()> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(());
        }

        if data.len() > RX_BUFFER_SIZE {
            return Err(());
        }

        let cur = self.tx_cur.load(Ordering::SeqCst) as usize;

        // SAFETY: Accessing static DMA buffers, single-threaded NIC access via atomic guards
        unsafe {
            let tx_descs = addr_of_mut!(STATIC_TX_DESCS) as *mut [TxDesc; NUM_TX_DESC];
            let tx_bufs = addr_of_mut!(STATIC_TX_BUFS) as *mut [[u8; RX_BUFFER_SIZE]; NUM_TX_DESC];

            while ((*tx_descs)[cur].status & DESC_DD) == 0 {
                core::hint::spin_loop();
            }

            let buf_ptr = (*tx_bufs)[cur].as_mut_ptr();
            core::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr, data.len());

            (*tx_descs)[cur].length = data.len() as u16;
            (*tx_descs)[cur].cmd = DESC_CMD_EOP | DESC_CMD_IFCS | DESC_CMD_RS;
            (*tx_descs)[cur].status = 0;
        }

        let next = ((cur + 1) % NUM_TX_DESC) as u32;
        self.tx_cur.store(next, Ordering::SeqCst);
        self.write_reg(REG_TDT, next);

        Ok(())
    }

    pub fn recv(&self) -> Option<Vec<u8>> {
        self.poll_rx();
        self.rx_queue.lock().pop()
    }
}

impl SmolDevice for E1000 {
    fn now_ms(&self) -> u64 {
        crate::time::timestamp_millis()
    }

    fn recv(&self) -> Option<Vec<u8>> {
        self.recv()
    }

    fn transmit(&self, frame: &[u8]) -> Result<(), ()> {
        self.transmit(frame)
    }

    fn mac(&self) -> [u8; 6] {
        self.mac
    }
}

fn find_e1000_device() -> Option<PciDevice> {
    find_device(0x02, 0x00, None)
}

static E1000_DRIVER: spin::Once<E1000> = spin::Once::new();
static E1000_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init() -> Result<(), &'static str> {
    serial::println(b"[E1000] Probing for Intel NIC...");

    if E1000_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(());
    }

    let mut driver = match E1000::new() {
        Some(d) => d,
        None => {
            serial::println(b"[E1000] No compatible NIC found");
            return Err("No e1000 found");
        }
    };

    driver.init()?;

    E1000_DRIVER.call_once(|| driver);
    E1000_INITIALIZED.store(true, Ordering::SeqCst);

    Ok(())
}

pub fn is_initialized() -> bool {
    E1000_INITIALIZED.load(Ordering::SeqCst)
}

pub fn get_driver() -> Option<&'static dyn SmolDevice> {
    E1000_DRIVER.get().map(|e| e as &'static dyn SmolDevice)
}

pub fn poll() {
    if let Some(driver) = E1000_DRIVER.get() {
        driver.poll_rx();
    }
}
