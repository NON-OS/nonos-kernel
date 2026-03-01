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

//! TPM Driver Implementation

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use super::constants::*;
use super::error::{_parse_response_code, response_codes, _ResponseCodeInfo, TpmError, TpmResult};
use super::mmio::{delay_ms, mmio_read8, mmio_read32, mmio_write8, mmio_write32, spin_delay};
use super::status::PcrBankConfig;
use crate::drivers::security::rate_limiter::{DriverOpType, RateLimiter};

pub(super) struct TpmDriver {
    base: u64,
    locality: u8,
    initialized: AtomicBool,
    manufacturer: u32,
    version: u32,
    _buffer: Mutex<[u8; TPM_BUFFER_SIZE]>,
    _pcr_banks: Mutex<PcrBankConfig>,
    command_rate_limiter: RateLimiter,
    random_rate_limiter: RateLimiter,
}

impl TpmDriver {
    pub(super) fn new() -> Self {
        Self {
            base: TPM_LOCALITY_0,
            locality: 0,
            initialized: AtomicBool::new(false),
            manufacturer: 0,
            version: 0,
            _buffer: Mutex::new([0u8; TPM_BUFFER_SIZE]),
            _pcr_banks: Mutex::new(PcrBankConfig::default()),
            command_rate_limiter: RateLimiter::new(TPM_MAX_COMMANDS_PER_SEC),
            random_rate_limiter: RateLimiter::new(TPM_MAX_RANDOM_REQUESTS_PER_SEC),
        }
    }

    pub(super) fn probe(&self) -> bool {
        unsafe {
            let did_vid = mmio_read32(self.base + regs::TPM_DID_VID);

            if did_vid == 0xFFFF_FFFF || did_vid == 0 {
                return false;
            }

            let intf_id = mmio_read32(self.base + regs::TPM_INTERFACE_ID);

            let intf_type = intf_id & 0x0F;
            if intf_type > 1 {
                return false;
            }

            let status = mmio_read32(self.base + regs::TPM_STS);
            (status & sts::TPM_STS_FAMILY_TPM2) != 0
        }
    }

    fn request_locality(&mut self, locality: u8) -> TpmResult<()> {
        if locality > 4 {
            return Err(TpmError::InvalidParameter);
        }

        let locality_base = TPM_MMIO_BASE + (locality as u64 * 0x1000);

        unsafe {
            mmio_write8(
                locality_base + regs::TPM_ACCESS,
                access::TPM_ACCESS_REQUEST_USE,
            );

            for _ in 0..LOCALITY_REQUEST_TIMEOUT_MS {
                let access_reg = mmio_read8(locality_base + regs::TPM_ACCESS);

                if (access_reg & access::TPM_ACCESS_ACTIVE_LOCALITY) != 0 {
                    self.base = locality_base;
                    self.locality = locality;
                    return Ok(());
                }

                delay_ms(1);
            }
        }

        Err(TpmError::Timeout)
    }

    fn wait_for_command_ready(&self) -> TpmResult<()> {
        unsafe {
            for _ in 0..COMMAND_READY_TIMEOUT_MS {
                let status = mmio_read32(self.base + regs::TPM_STS);

                if (status & sts::TPM_STS_COMMAND_READY) != 0 {
                    return Ok(());
                }

                mmio_write32(self.base + regs::TPM_STS, sts::TPM_STS_COMMAND_READY);

                spin_delay(1000);
            }
        }
        Err(TpmError::Timeout)
    }

    fn get_burst_count(&self) -> u16 {
        unsafe {
            let status = mmio_read32(self.base + regs::TPM_STS);
            ((status >> 8) & 0xFFFF) as u16
        }
    }

    fn send_command(&self, cmd: &[u8]) -> TpmResult<()> {
        self.wait_for_command_ready()?;

        unsafe {
            let mut sent = 0;

            while sent < cmd.len() {
                let burst = self.get_burst_count() as usize;
                if burst == 0 {
                    spin_delay(100);
                    continue;
                }

                let to_send = core::cmp::min(burst, cmd.len() - sent);
                for i in 0..to_send {
                    mmio_write8(self.base + regs::TPM_DATA_FIFO, cmd[sent + i]);
                }
                sent += to_send;
            }

            let status = mmio_read32(self.base + regs::TPM_STS);
            if (status & sts::TPM_STS_VALID) == 0 {
                return Err(TpmError::InvalidResponse);
            }

            mmio_write32(self.base + regs::TPM_STS, sts::TPM_STS_GO);
        }

        Ok(())
    }

    fn receive_response(&self, buf: &mut [u8]) -> TpmResult<usize> {
        unsafe {
            for _ in 0..RESPONSE_TIMEOUT_MS {
                let status = mmio_read32(self.base + regs::TPM_STS);

                if (status & sts::TPM_STS_DATA_AVAIL) != 0 {
                    break;
                }

                spin_delay(1000);
            }

            let status = mmio_read32(self.base + regs::TPM_STS);
            if (status & sts::TPM_STS_DATA_AVAIL) == 0 {
                return Err(TpmError::Timeout);
            }

            if buf.len() < 10 {
                return Err(TpmError::BufferTooSmall);
            }

            let mut received = 0;

            while received < 10 {
                let burst = self.get_burst_count();
                if burst == 0 {
                    spin_delay(100);
                    continue;
                }
                buf[received] = mmio_read8(self.base + regs::TPM_DATA_FIFO);
                received += 1;
            }

            let response_size =
                u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]) as usize;

            if response_size > buf.len() {
                return Err(TpmError::BufferTooSmall);
            }

            while received < response_size {
                let burst = self.get_burst_count() as usize;
                if burst == 0 {
                    spin_delay(100);
                    continue;
                }

                let to_read = core::cmp::min(burst, response_size - received);
                for _ in 0..to_read {
                    if received >= buf.len() {
                        break;
                    }
                    buf[received] = mmio_read8(self.base + regs::TPM_DATA_FIFO);
                    received += 1;
                }
            }

            mmio_write32(self.base + regs::TPM_STS, sts::TPM_STS_COMMAND_READY);

            Ok(received)
        }
    }

    pub(super) fn execute_command(&self, cmd: &[u8], response: &mut [u8]) -> TpmResult<usize> {
        if self.command_rate_limiter.check_rate(DriverOpType::ControlOp).is_err() {
            return Err(TpmError::RateLimitExceeded);
        }
        self.send_command(cmd)?;
        self.receive_response(response)
    }

    pub(super) fn init(&mut self) -> TpmResult<()> {
        if !self.probe() {
            return Err(TpmError::NotPresent);
        }

        self.request_locality(0)?;

        unsafe {
            self.manufacturer = mmio_read32(self.base + regs::TPM_DID_VID);
            self.version = mmio_read32(self.base + regs::TPM_RID);
        }

        self.startup(false)?;

        self.self_test(true)?;

        self.initialized.store(true, Ordering::SeqCst);

        crate::log_info!(
            "[TPM] TPM 2.0 initialized: manufacturer=0x{:08X} version=0x{:08X}",
            self.manufacturer,
            self.version
        );

        Ok(())
    }

    fn startup(&self, resume: bool) -> TpmResult<()> {
        let mut cmd = [0u8; 12];

        cmd[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd[2..6].copy_from_slice(&12u32.to_be_bytes());
        cmd[6..10].copy_from_slice(&commands::TPM2_CC_STARTUP.to_be_bytes());

        let su_type = if resume {
            startup::TPM2_SU_STATE
        } else {
            startup::TPM2_SU_CLEAR
        };
        cmd[10..12].copy_from_slice(&su_type.to_be_bytes());

        let mut response = [0u8; 10];
        self.execute_command(&cmd, &mut response)?;

        let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        if rc != 0 && rc != response_codes::TPM_RC_INITIALIZE {
            return Err(TpmError::CommandFailed(rc));
        }

        Ok(())
    }

    fn self_test(&self, full: bool) -> TpmResult<()> {
        let mut cmd = [0u8; 11];

        cmd[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd[2..6].copy_from_slice(&11u32.to_be_bytes());
        cmd[6..10].copy_from_slice(&commands::TPM2_CC_SELF_TEST.to_be_bytes());
        cmd[10] = if full { 1 } else { 0 };

        let mut response = [0u8; 10];
        self.execute_command(&cmd, &mut response)?;

        let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        if rc != 0 {
            return Err(TpmError::CommandFailed(rc));
        }

        Ok(())
    }

    pub(super) fn pcr_extend(&self, pcr_index: u32, hash_alg: u16, digest: &[u8]) -> TpmResult<()> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(TpmError::NotInitialized);
        }

        if pcr_index >= TPM_NUM_PCRS as u32 {
            return Err(TpmError::InvalidParameter);
        }

        let expected_digest_len = match hash_alg {
            alg::TPM2_ALG_SHA1 => 20,
            alg::TPM2_ALG_SHA256 => 32,
            alg::TPM2_ALG_SHA384 => 48,
            alg::TPM2_ALG_SHA512 => 64,
            _ => return Err(TpmError::InvalidParameter),
        };

        if digest.len() != expected_digest_len {
            return Err(TpmError::InvalidParameter);
        }

        let cmd_size: u32 = 10 + 4 + 4 + 9 + 4 + 2 + (expected_digest_len as u32);

        let mut cmd = Vec::with_capacity(cmd_size as usize);

        cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&cmd_size.to_be_bytes());
        cmd.extend_from_slice(&commands::TPM2_CC_PCR_EXTEND.to_be_bytes());

        cmd.extend_from_slice(&pcr_index.to_be_bytes());

        let auth_size = 9u32;
        cmd.extend_from_slice(&auth_size.to_be_bytes());
        cmd.extend_from_slice(&TPM_RS_PW.to_be_bytes());
        cmd.extend_from_slice(&0u16.to_be_bytes());
        cmd.push(0);
        cmd.extend_from_slice(&0u16.to_be_bytes());

        cmd.extend_from_slice(&1u32.to_be_bytes());

        cmd.extend_from_slice(&hash_alg.to_be_bytes());
        cmd.extend_from_slice(digest);

        debug_assert_eq!(cmd.len(), cmd_size as usize, "PCR_Extend command size mismatch");

        let mut response = [0u8; 64];
        self.execute_command(&cmd, &mut response)?;

        let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        if rc != 0 {
            return Err(TpmError::CommandFailed(rc));
        }

        Ok(())
    }

    pub(super) fn pcr_read(&self, pcr_index: u32, hash_alg: u16) -> TpmResult<Vec<u8>> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(TpmError::NotInitialized);
        }

        if pcr_index >= TPM_NUM_PCRS as u32 {
            return Err(TpmError::InvalidParameter);
        }

        const CMD_SIZE: u32 = 10 + 10;

        let mut cmd = Vec::with_capacity(CMD_SIZE as usize);

        cmd.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&CMD_SIZE.to_be_bytes());
        cmd.extend_from_slice(&commands::TPM2_CC_PCR_READ.to_be_bytes());

        cmd.extend_from_slice(&1u32.to_be_bytes());
        cmd.extend_from_slice(&hash_alg.to_be_bytes());
        cmd.push(3);

        let byte_idx = (pcr_index / 8) as usize;
        let bit_idx = (pcr_index % 8) as u8;
        let mut pcr_select = [0u8; 3];
        pcr_select[byte_idx] = 1 << bit_idx;
        cmd.extend_from_slice(&pcr_select);

        debug_assert_eq!(cmd.len(), CMD_SIZE as usize, "PCR_Read command size mismatch");

        let mut response = [0u8; 256];
        let resp_size = self.execute_command(&cmd, &mut response)?;

        let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        if rc != 0 {
            return Err(TpmError::CommandFailed(rc));
        }

        const HEADER_SIZE: usize = 10;
        const UPDATE_COUNTER_SIZE: usize = 4;
        const PCR_SELECTION_OUT_SIZE: usize = 10;
        const DIGEST_COUNT_SIZE: usize = 4;
        const DIGEST_SIZE_FIELD: usize = 2;

        let preamble = HEADER_SIZE + UPDATE_COUNTER_SIZE + PCR_SELECTION_OUT_SIZE + DIGEST_COUNT_SIZE;

        if resp_size < preamble + DIGEST_SIZE_FIELD {
            return Err(TpmError::InvalidResponse);
        }

        let digest_count = u32::from_be_bytes([
            response[HEADER_SIZE + UPDATE_COUNTER_SIZE + PCR_SELECTION_OUT_SIZE],
            response[HEADER_SIZE + UPDATE_COUNTER_SIZE + PCR_SELECTION_OUT_SIZE + 1],
            response[HEADER_SIZE + UPDATE_COUNTER_SIZE + PCR_SELECTION_OUT_SIZE + 2],
            response[HEADER_SIZE + UPDATE_COUNTER_SIZE + PCR_SELECTION_OUT_SIZE + 3],
        ]);

        if digest_count == 0 {
            return Err(TpmError::InvalidResponse);
        }

        let digest_size = u16::from_be_bytes([response[preamble], response[preamble + 1]]) as usize;

        if resp_size < preamble + DIGEST_SIZE_FIELD + digest_size {
            return Err(TpmError::InvalidResponse);
        }

        Ok(response[preamble + DIGEST_SIZE_FIELD..preamble + DIGEST_SIZE_FIELD + digest_size].to_vec())
    }

    pub(super) fn get_random(&self, count: u16) -> TpmResult<Vec<u8>> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(TpmError::NotInitialized);
        }

        if self.random_rate_limiter.check_rate(DriverOpType::ControlOp).is_err() {
            return Err(TpmError::RateLimitExceeded);
        }

        if count > TPM_MAX_RANDOM_BYTES {
            return Err(TpmError::InvalidParameter);
        }

        let mut cmd = [0u8; 12];
        cmd[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd[2..6].copy_from_slice(&12u32.to_be_bytes());
        cmd[6..10].copy_from_slice(&commands::TPM2_CC_GET_RANDOM.to_be_bytes());
        cmd[10..12].copy_from_slice(&count.to_be_bytes());

        let mut response = [0u8; 128];
        let resp_size = self.execute_command(&cmd, &mut response)?;

        let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        if rc != 0 {
            return Err(TpmError::CommandFailed(rc));
        }

        if resp_size < 12 {
            return Err(TpmError::InvalidResponse);
        }

        let random_size = u16::from_be_bytes([response[10], response[11]]) as usize;
        if resp_size < 12 + random_size {
            return Err(TpmError::InvalidResponse);
        }

        Ok(response[12..12 + random_size].to_vec())
    }

    pub(super) fn shutdown(&self, state_save: bool) -> TpmResult<()> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(TpmError::NotInitialized);
        }

        let mut cmd = [0u8; 12];
        cmd[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        cmd[2..6].copy_from_slice(&12u32.to_be_bytes());
        cmd[6..10].copy_from_slice(&commands::TPM2_CC_SHUTDOWN.to_be_bytes());

        let su_type = if state_save {
            startup::TPM2_SU_STATE
        } else {
            startup::TPM2_SU_CLEAR
        };
        cmd[10..12].copy_from_slice(&su_type.to_be_bytes());

        let mut response = [0u8; 10];
        self.execute_command(&cmd, &mut response)?;

        Ok(())
    }

    pub(super) fn create_quote(&self, pcr_selection: &[u32], nonce: &[u8]) -> TpmResult<Vec<u8>> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(TpmError::NotInitialized);
        }

        if pcr_selection.is_empty() || pcr_selection.len() > TPM_NUM_PCRS {
            return Err(TpmError::InvalidParameter);
        }

        if nonce.len() > TPM_MAX_DIGEST_SIZE {
            return Err(TpmError::InvalidParameter);
        }

        let cmd_size: u32 = 10 + 4 + 4 + 9 + 2 + (nonce.len() as u32) + 2 + 10;

        let mut cmd = Vec::with_capacity(cmd_size as usize);

        cmd.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
        cmd.extend_from_slice(&cmd_size.to_be_bytes());
        cmd.extend_from_slice(&commands::TPM2_CC_QUOTE.to_be_bytes());

        cmd.extend_from_slice(&TPM_RH_ENDORSEMENT.to_be_bytes());

        let auth_size = 9u32;
        cmd.extend_from_slice(&auth_size.to_be_bytes());
        cmd.extend_from_slice(&TPM_RS_PW.to_be_bytes());
        cmd.extend_from_slice(&0u16.to_be_bytes());
        cmd.push(0);
        cmd.extend_from_slice(&0u16.to_be_bytes());

        cmd.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
        cmd.extend_from_slice(nonce);

        cmd.extend_from_slice(&alg::TPM2_ALG_NULL.to_be_bytes());

        cmd.extend_from_slice(&1u32.to_be_bytes());
        cmd.extend_from_slice(&alg::TPM2_ALG_SHA256.to_be_bytes());
        cmd.push(3);

        let mut pcr_bitmap = [0u8; 3];
        for &pcr in pcr_selection {
            if pcr < TPM_NUM_PCRS as u32 {
                let byte_idx = (pcr / 8) as usize;
                let bit_idx = (pcr % 8) as u8;
                pcr_bitmap[byte_idx] |= 1 << bit_idx;
            }
        }
        cmd.extend_from_slice(&pcr_bitmap);

        debug_assert_eq!(cmd.len(), cmd_size as usize, "Quote command size mismatch");

        let mut response = [0u8; 1024];
        let resp_size = self.execute_command(&cmd, &mut response)?;

        let rc = u32::from_be_bytes([response[6], response[7], response[8], response[9]]);
        if rc != 0 {
            crate::log_warn!("[TPM] Quote failed with code 0x{:08x}", rc);
            return Err(TpmError::CommandFailed(rc));
        }

        if resp_size < 14 {
            return Err(TpmError::InvalidResponse);
        }

        Ok(response[10..resp_size].to_vec())
    }

    pub(super) fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    pub(super) fn get_locality(&self) -> u8 {
        self.locality
    }

    pub(super) fn get_manufacturer(&self) -> u32 {
        self.manufacturer
    }

    pub(super) fn get_version(&self) -> u32 {
        self.version
    }

    pub(super) fn _get_buffer_copy(&self) -> [u8; TPM_BUFFER_SIZE] {
        *self._buffer.lock()
    }

    pub(super) fn _get_pcr_banks(&self) -> PcrBankConfig {
        self._pcr_banks.lock().clone()
    }

    pub(super) fn _set_pcr_banks(&self, config: PcrBankConfig) {
        *self._pcr_banks.lock() = config;
    }

    pub(super) fn _parse_last_error(response_code: u32) -> _ResponseCodeInfo {
        _parse_response_code(response_code)
    }
}

impl Default for TpmDriver {
    fn default() -> Self {
        Self::new()
    }
}
