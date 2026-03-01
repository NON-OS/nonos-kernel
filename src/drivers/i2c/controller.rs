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

use super::error::I2cError;
use super::types::{I2cAbortSource, I2cSpeed};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use x86_64::{VirtAddr, PhysAddr};
use crate::memory::nonos_paging::{map_page, PagePermissions};

const IC_CON: u64 = 0x00;
const IC_TAR: u64 = 0x04;
const _IC_SAR: u64 = 0x08;
const _IC_HS_MADDR: u64 = 0x0C;
const IC_DATA_CMD: u64 = 0x10;
const IC_SS_SCL_HCNT: u64 = 0x14;
const IC_SS_SCL_LCNT: u64 = 0x18;
const IC_FS_SCL_HCNT: u64 = 0x1C;
const IC_FS_SCL_LCNT: u64 = 0x20;
const IC_HS_SCL_HCNT: u64 = 0x24;
const IC_HS_SCL_LCNT: u64 = 0x28;
const _IC_INTR_STAT: u64 = 0x2C;
const IC_INTR_MASK: u64 = 0x30;
const IC_RAW_INTR_STAT: u64 = 0x34;
const IC_RX_TL: u64 = 0x38;
const IC_TX_TL: u64 = 0x3C;
const IC_CLR_INTR: u64 = 0x40;
const _IC_CLR_RX_UNDER: u64 = 0x44;
const _IC_CLR_RX_OVER: u64 = 0x48;
const _IC_CLR_TX_OVER: u64 = 0x4C;
const _IC_CLR_RD_REQ: u64 = 0x50;
const IC_CLR_TX_ABRT: u64 = 0x54;
const _IC_CLR_RX_DONE: u64 = 0x58;
const _IC_CLR_ACTIVITY: u64 = 0x5C;
const IC_CLR_STOP_DET: u64 = 0x60;
const _IC_CLR_START_DET: u64 = 0x64;
const _IC_CLR_GEN_CALL: u64 = 0x68;
const IC_ENABLE: u64 = 0x6C;
const IC_STATUS: u64 = 0x70;
const IC_TXFLR: u64 = 0x74;
const IC_RXFLR: u64 = 0x78;
const IC_SDA_HOLD: u64 = 0x7C;
const IC_TX_ABRT_SOURCE: u64 = 0x80;
const _IC_SLV_DATA_NACK_ONLY: u64 = 0x84;
const _IC_DMA_CR: u64 = 0x88;
const _IC_DMA_TDLR: u64 = 0x8C;
const _IC_DMA_RDLR: u64 = 0x90;
const _IC_SDA_SETUP: u64 = 0x94;
const _IC_ACK_GENERAL_CALL: u64 = 0x98;
const IC_ENABLE_STATUS: u64 = 0x9C;
const IC_FS_SPKLEN: u64 = 0xA0;
const IC_HS_SPKLEN: u64 = 0xA4;
const _IC_CLR_RESTART_DET: u64 = 0xA8;
const IC_COMP_PARAM_1: u64 = 0xF4;
const _IC_COMP_VERSION: u64 = 0xF8;
const IC_COMP_TYPE: u64 = 0xFC;

const IC_CON_MASTER_MODE: u32 = 1 << 0;
const IC_CON_SPEED_SS: u32 = 1 << 1;
const IC_CON_SPEED_FS: u32 = 2 << 1;
const IC_CON_SPEED_HS: u32 = 3 << 1;
const IC_CON_SPEED_MASK: u32 = 3 << 1;
const _IC_CON_10BITADDR_SLAVE: u32 = 1 << 3;
const _IC_CON_10BITADDR_MASTER: u32 = 1 << 4;
const IC_CON_RESTART_EN: u32 = 1 << 5;
const IC_CON_SLAVE_DISABLE: u32 = 1 << 6;
const _IC_CON_STOP_DET_IFADDRESSED: u32 = 1 << 7;
const _IC_CON_TX_EMPTY_CTRL: u32 = 1 << 8;
const _IC_CON_RX_FIFO_FULL_HLD_CTRL: u32 = 1 << 9;

const IC_DATA_CMD_READ: u32 = 1 << 8;
const IC_DATA_CMD_STOP: u32 = 1 << 9;
const _IC_DATA_CMD_RESTART: u32 = 1 << 10;

const _IC_INTR_RX_UNDER: u32 = 1 << 0;
const _IC_INTR_RX_OVER: u32 = 1 << 1;
const _IC_INTR_RX_FULL: u32 = 1 << 2;
const _IC_INTR_TX_OVER: u32 = 1 << 3;
const _IC_INTR_TX_EMPTY: u32 = 1 << 4;
const _IC_INTR_RD_REQ: u32 = 1 << 5;
const IC_INTR_TX_ABRT: u32 = 1 << 6;
const _IC_INTR_RX_DONE: u32 = 1 << 7;
const _IC_INTR_ACTIVITY: u32 = 1 << 8;
const IC_INTR_STOP_DET: u32 = 1 << 9;
const _IC_INTR_START_DET: u32 = 1 << 10;
const _IC_INTR_GEN_CALL: u32 = 1 << 11;
const _IC_INTR_RESTART_DET: u32 = 1 << 12;
const _IC_INTR_MST_ON_HOLD: u32 = 1 << 13;

const _IC_STATUS_ACTIVITY: u32 = 1 << 0;
const _IC_STATUS_TFNF: u32 = 1 << 1;
const IC_STATUS_TFE: u32 = 1 << 2;
const IC_STATUS_RFNE: u32 = 1 << 3;
const _IC_STATUS_RFF: u32 = 1 << 4;
const IC_STATUS_MST_ACTIVITY: u32 = 1 << 5;
const _IC_STATUS_SLV_ACTIVITY: u32 = 1 << 6;

const IC_ENABLE_ENABLE: u32 = 1 << 0;
const _IC_ENABLE_ABORT: u32 = 1 << 1;
const _IC_ENABLE_TX_CMD_BLOCK: u32 = 1 << 2;

const _IC_TAR_10BITADDR_MASTER: u32 = 1 << 12;

const TIMEOUT_US: u64 = 100_000;
const DW_IC_COMP_TYPE_VALUE: u32 = 0x44570140;

const I2C_MMIO_SIZE: usize = 0x1000;

static NEXT_I2C_MMIO: AtomicU64 = AtomicU64::new(0xFFFF_8900_0000_0000);

fn map_i2c_mmio(phys_addr: u64) -> Option<u64> {
    let phys = PhysAddr::new(phys_addr);
    let virt_base = NEXT_I2C_MMIO.fetch_add(I2C_MMIO_SIZE as u64, Ordering::SeqCst);
    let virt = VirtAddr::new(virt_base);

    let permissions = PagePermissions::READ | PagePermissions::WRITE |
                     PagePermissions::NO_CACHE | PagePermissions::DEVICE;

    if let Err(_) = map_page(virt, phys, permissions) {
        return None;
    }

    Some(virt_base)
}

pub struct DesignWareI2c {
    base: u64,
    speed: I2cSpeed,
    input_clock_hz: u32,
    tx_fifo_depth: u32,
    rx_fifo_depth: u32,
    initialized: AtomicBool,
}

impl DesignWareI2c {
    pub fn new(phys_base: u64, input_clock_hz: u32) -> Option<Self> {
        let virt_base = map_i2c_mmio(phys_base)?;

        Some(Self {
            base: virt_base,
            speed: I2cSpeed::Fast,
            input_clock_hz,
            tx_fifo_depth: 64,
            rx_fifo_depth: 64,
            initialized: AtomicBool::new(false),
        })
    }

    pub fn base_address(&self) -> u64 {
        self.base
    }

    pub fn init(&mut self) -> Result<(), I2cError> {
        let comp_type = self.read_reg(IC_COMP_TYPE);
        if comp_type != DW_IC_COMP_TYPE_VALUE {
            crate::log_warn!(
                "i2c: unexpected component type 0x{:08x}, expected 0x{:08x}",
                comp_type,
                DW_IC_COMP_TYPE_VALUE
            );
        }

        let comp_param = self.read_reg(IC_COMP_PARAM_1);
        self.tx_fifo_depth = ((comp_param >> 16) & 0xFF) + 1;
        self.rx_fifo_depth = ((comp_param >> 8) & 0xFF) + 1;

        self.disable()?;

        let con = IC_CON_MASTER_MODE
            | IC_CON_SLAVE_DISABLE
            | IC_CON_RESTART_EN
            | self.speed_to_con_bits();

        self.write_reg(IC_CON, con);

        self.configure_speed()?;

        self.write_reg(IC_INTR_MASK, 0);
        let _ = self.read_reg(IC_CLR_INTR);

        self.write_reg(IC_RX_TL, 0);
        self.write_reg(IC_TX_TL, self.tx_fifo_depth / 2);

        let sda_hold = self.calculate_sda_hold();
        self.write_reg(IC_SDA_HOLD, sda_hold);

        self.initialized.store(true, Ordering::SeqCst);

        crate::log::info!(
            "i2c: DesignWare controller at 0x{:x}, TX FIFO {}, RX FIFO {}",
            self.base,
            self.tx_fifo_depth,
            self.rx_fifo_depth
        );

        Ok(())
    }

    pub fn set_speed(&mut self, speed: I2cSpeed) -> Result<(), I2cError> {
        self.speed = speed;
        self.disable()?;

        let mut con = self.read_reg(IC_CON);
        con &= !IC_CON_SPEED_MASK;
        con |= self.speed_to_con_bits();
        self.write_reg(IC_CON, con);

        self.configure_speed()
    }

    pub fn transfer(
        &self,
        addr: u8,
        write_data: &[u8],
        read_buf: &mut [u8],
    ) -> Result<(), I2cError> {
        if !self.initialized.load(Ordering::Relaxed) {
            return Err(I2cError::NotInitialized);
        }

        self.wait_bus_not_busy()?;
        self.enable()?;

        self.set_target_address(addr)?;

        let write_len = write_data.len();
        let read_len = read_buf.len();
        let total = write_len + read_len;

        let mut write_idx = 0;
        let mut read_idx = 0;
        let mut cmd_idx = 0;

        while cmd_idx < total || read_idx < read_len {
            let raw_stat = self.read_reg(IC_RAW_INTR_STAT);
            if raw_stat & IC_INTR_TX_ABRT != 0 {
                let abort_src = self.read_reg(IC_TX_ABRT_SOURCE);
                let _ = self.read_reg(IC_CLR_TX_ABRT);
                self.disable()?;

                if let Some(src) = I2cAbortSource::from_bits(abort_src) {
                    match src {
                        I2cAbortSource::SevenBitAddrNack
                        | I2cAbortSource::TenBitAddr1Nack
                        | I2cAbortSource::TenBitAddr2Nack
                        | I2cAbortSource::TxDataNack => return Err(I2cError::Nack),
                        I2cAbortSource::ArbitrationLost => {
                            return Err(I2cError::ArbitrationLost)
                        }
                        _ => return Err(I2cError::TxAbort),
                    }
                }
                return Err(I2cError::TxAbort);
            }

            while read_idx < read_len && (self.read_reg(IC_STATUS) & IC_STATUS_RFNE) != 0 {
                read_buf[read_idx] = (self.read_reg(IC_DATA_CMD) & 0xFF) as u8;
                read_idx += 1;
            }

            if cmd_idx < total {
                let tx_limit = self.tx_fifo_depth - self.read_reg(IC_TXFLR);
                let rx_limit = self.rx_fifo_depth - self.read_reg(IC_RXFLR);

                while cmd_idx < total && tx_limit > 0 && rx_limit > 0 {
                    let is_last = cmd_idx == total - 1;

                    let mut cmd = if cmd_idx < write_len {
                        let c = write_data[write_idx] as u32;
                        write_idx += 1;
                        c
                    } else {
                        IC_DATA_CMD_READ
                    };

                    if is_last {
                        cmd |= IC_DATA_CMD_STOP;
                    }

                    self.write_reg(IC_DATA_CMD, cmd);
                    cmd_idx += 1;

                    if cmd_idx >= total {
                        break;
                    }
                }
            }

            if cmd_idx >= total && read_idx < read_len {
                self.wait_rx_data()?;
            }
        }

        self.wait_transfer_complete()?;
        self.disable()?;

        Ok(())
    }

    pub fn read(&self, addr: u8, reg: u8, buf: &mut [u8]) -> Result<(), I2cError> {
        self.transfer(addr, &[reg], buf)
    }

    pub fn write(&self, addr: u8, reg: u8, data: &[u8]) -> Result<(), I2cError> {
        if data.is_empty() {
            return self.transfer(addr, &[reg], &mut []);
        }

        let mut write_buf = alloc::vec![0u8; data.len() + 1];
        write_buf[0] = reg;
        write_buf[1..].copy_from_slice(data);

        self.transfer(addr, &write_buf, &mut [])
    }

    pub fn write_read(
        &self,
        addr: u8,
        write_data: &[u8],
        read_buf: &mut [u8],
    ) -> Result<(), I2cError> {
        self.transfer(addr, write_data, read_buf)
    }

    pub fn probe(&self, addr: u8) -> bool {
        if !self.initialized.load(Ordering::Relaxed) {
            return false;
        }

        if self.wait_bus_not_busy().is_err() {
            return false;
        }
        if self.enable().is_err() {
            return false;
        }
        if self.set_target_address(addr).is_err() {
            let _ = self.disable();
            return false;
        }

        self.write_reg(IC_DATA_CMD, IC_DATA_CMD_STOP);

        let start = timestamp();
        let mut found = false;

        while timestamp() - start < 10_000 {
            let raw_stat = self.read_reg(IC_RAW_INTR_STAT);

            if raw_stat & IC_INTR_TX_ABRT != 0 {
                let _ = self.read_reg(IC_CLR_TX_ABRT);
                break;
            }

            if raw_stat & IC_INTR_STOP_DET != 0 {
                let _ = self.read_reg(IC_CLR_STOP_DET);
                found = true;
                break;
            }

            core::hint::spin_loop();
        }

        let _ = self.disable();
        found
    }

    fn enable(&self) -> Result<(), I2cError> {
        self.write_reg(IC_ENABLE, IC_ENABLE_ENABLE);

        let start = timestamp();
        while timestamp() - start < TIMEOUT_US {
            if (self.read_reg(IC_ENABLE_STATUS) & 1) != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }

        Err(I2cError::Timeout)
    }

    fn disable(&self) -> Result<(), I2cError> {
        self.write_reg(IC_ENABLE, 0);

        let start = timestamp();
        while timestamp() - start < TIMEOUT_US {
            if (self.read_reg(IC_ENABLE_STATUS) & 1) == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }

        Err(I2cError::Timeout)
    }

    fn set_target_address(&self, addr: u8) -> Result<(), I2cError> {
        let was_enabled = (self.read_reg(IC_ENABLE) & IC_ENABLE_ENABLE) != 0;

        if was_enabled {
            self.disable()?;
        }

        self.write_reg(IC_TAR, (addr & 0x7F) as u32);

        if was_enabled {
            self.enable()?;
        }

        Ok(())
    }

    fn wait_bus_not_busy(&self) -> Result<(), I2cError> {
        let start = timestamp();
        while timestamp() - start < TIMEOUT_US {
            let status = self.read_reg(IC_STATUS);
            if (status & IC_STATUS_MST_ACTIVITY) == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(I2cError::BusBusy)
    }

    fn wait_rx_data(&self) -> Result<(), I2cError> {
        let start = timestamp();
        while timestamp() - start < TIMEOUT_US {
            if (self.read_reg(IC_STATUS) & IC_STATUS_RFNE) != 0 {
                return Ok(());
            }
            if (self.read_reg(IC_RAW_INTR_STAT) & IC_INTR_TX_ABRT) != 0 {
                return Err(I2cError::TxAbort);
            }
            core::hint::spin_loop();
        }
        Err(I2cError::Timeout)
    }

    fn wait_transfer_complete(&self) -> Result<(), I2cError> {
        let start = timestamp();
        while timestamp() - start < TIMEOUT_US {
            let status = self.read_reg(IC_STATUS);
            if (status & IC_STATUS_TFE) != 0 && (status & IC_STATUS_MST_ACTIVITY) == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(I2cError::Timeout)
    }

    fn configure_speed(&self) -> Result<(), I2cError> {
        let ic_clk = self.input_clock_hz;

        match self.speed {
            I2cSpeed::Standard => {
                let hcnt = (ic_clk / 100_000 / 2) - 7;
                let lcnt = (ic_clk / 100_000 / 2) - 1;
                self.write_reg(IC_SS_SCL_HCNT, hcnt.max(6));
                self.write_reg(IC_SS_SCL_LCNT, lcnt.max(8));
            }
            I2cSpeed::Fast | I2cSpeed::FastPlus => {
                let freq = self.speed.frequency_hz();
                let hcnt = (ic_clk / freq / 2) - 7;
                let lcnt = (ic_clk / freq / 2) - 1;
                self.write_reg(IC_FS_SCL_HCNT, hcnt.max(6));
                self.write_reg(IC_FS_SCL_LCNT, lcnt.max(8));

                let spklen = if self.speed == I2cSpeed::FastPlus {
                    ic_clk / 20_000_000
                } else {
                    ic_clk / 10_000_000
                };
                self.write_reg(IC_FS_SPKLEN, spklen.max(1));
            }
            I2cSpeed::High => {
                let hcnt = (ic_clk / 3_400_000 / 2) - 7;
                let lcnt = (ic_clk / 3_400_000 / 2) - 1;
                self.write_reg(IC_HS_SCL_HCNT, hcnt.max(6));
                self.write_reg(IC_HS_SCL_LCNT, lcnt.max(8));
                self.write_reg(IC_HS_SPKLEN, (ic_clk / 100_000_000).max(1));
            }
        }

        Ok(())
    }

    fn calculate_sda_hold(&self) -> u32 {
        let ic_clk_ns = 1_000_000_000 / self.input_clock_hz;
        let sda_hold_ns = 300;
        let sda_hold = sda_hold_ns / ic_clk_ns;
        sda_hold.max(1).min(0xFFFF)
    }

    fn speed_to_con_bits(&self) -> u32 {
        match self.speed {
            I2cSpeed::Standard => IC_CON_SPEED_SS,
            I2cSpeed::Fast | I2cSpeed::FastPlus => IC_CON_SPEED_FS,
            I2cSpeed::High => IC_CON_SPEED_HS,
        }
    }

    fn read_reg(&self, offset: u64) -> u32 {
        // SAFETY: MMIO register access to valid controller address
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }

    fn write_reg(&self, offset: u64, value: u32) {
        // SAFETY: MMIO register access to valid controller address
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }
}

impl Clone for DesignWareI2c {
    fn clone(&self) -> Self {
        Self {
            base: self.base,
            speed: self.speed,
            input_clock_hz: self.input_clock_hz,
            tx_fifo_depth: self.tx_fifo_depth,
            rx_fifo_depth: self.rx_fifo_depth,
            initialized: AtomicBool::new(self.initialized.load(Ordering::Relaxed)),
        }
    }
}

fn timestamp() -> u64 {
    crate::arch::x86_64::time::tsc::elapsed_us()
}
