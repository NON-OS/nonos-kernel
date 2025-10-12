//! Crypto-wrapping storage device.

#![no_std]

extern crate alloc;

use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::sync::atomic::Ordering;
use x86_64::VirtAddr;

use crate::storage::{
    DeviceCapabilities, DeviceInfo, DeviceStatistics, IoFlags, IoOperation, IoRequest, IoResult,
    IoStatus, PowerState, SmartData, StorageDevice,
};

pub struct CryptoDevice<D: StorageDevice + ?Sized> {
    inner: Arc<D>,
    key: [u8; 32],
    block_size: u32,
    stats: DeviceStatistics,
}

impl<D: StorageDevice + ?Sized> CryptoDevice<D> {
    pub fn new(inner: Arc<D>, key: [u8; 32]) -> Self {
        let info = inner.device_info();
        Self {
            inner,
            key,
            block_size: info.block_size,
            stats: DeviceStatistics::default(),
        }
    }

    #[inline]
    fn bs(&self) -> usize {
        self.block_size as usize
    }

    fn keystream(&self, lba: u64, out: &mut [u8]) {
        // BLAKE3 XOF-based keystream: chunked per 32 bytes.
        let mut offset = 0usize;
        let mut counter: u64 = 0;
        while offset < out.len() {
            let mut hasher = blake3::Hasher::new_keyed(&self.key);
            hasher.update(&lba.to_le_bytes());
            hasher.update(&counter.to_le_bytes());
            let chunk = hasher.finalize();
            let piece = core::cmp::min(32, out.len() - offset);
            out[offset..offset + piece].copy_from_slice(&chunk.as_bytes()[..piece]);
            offset += piece;
            counter = counter.wrapping_add(1);
        }
    }

    fn crypt_in_place(&self, lba: u64, buf: &mut [u8]) {
        let mut ks = vec![0u8; buf.len()];
        self.keystream(lba, &mut ks);
        for (b, k) in buf.iter_mut().zip(ks.iter()) {
            *b ^= *k;
        }
    }
}

impl<D: StorageDevice + ?Sized> StorageDevice for CryptoDevice<D> {
    fn device_info(&self) -> DeviceInfo {
        let mut info = self.inner.device_info();
        info.features |= DeviceCapabilities::ENCRYPTION;
        info.model = alloc::format!("{}+CRYPT", info.model);
        info
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.inner.capabilities() | DeviceCapabilities::ENCRYPTION
    }

    fn submit_request(&self, mut request: IoRequest) -> Result<(), IoStatus> {
        let blocks = request.block_count;
        let byte_len = blocks as usize * self.bs();
        if request.buffer_size < byte_len {
            return Err(IoStatus::InvalidRequest);
        }
        let start_lba = request.lba;

        match request.operation {
            IoOperation::Read => {
                // Read ciphertext into buffer, then decrypt in-place.
                self.inner.submit_request(IoRequest { completion_callback: None, ..request })?;
                unsafe {
                    let buf = core::slice::from_raw_parts_mut(request.buffer.as_mut_ptr::<u8>(), byte_len);
                    // Decrypt each block independently (keystream keyed by LBA)
                    for i in 0..blocks as u64 {
                        let off = (i as usize) * self.bs();
                        self.crypt_in_place(start_lba + i, &mut buf[off..off + self.bs()]);
                    }
                }
                if let Some(cb) = request.completion_callback.take() {
                    cb(IoResult {
                        status: IoStatus::Success,
                        bytes_transferred: byte_len,
                        error_code: 0,
                        completion_time: crate::time::timestamp_millis(),
                    });
                }
                Ok(())
            }
            IoOperation::Write => {
                // Encrypt into a temp bounce buffer to avoid mutating caller data in-place.
                let mut bounce = alloc::vec![0u8; byte_len];
                unsafe {
                    let src = core::slice::from_raw_parts(request.buffer.as_ptr::<u8>(), byte_len);
                    bounce.copy_from_slice(src);
                }
                for i in 0..blocks as u64 {
                    let off = (i as usize) * self.bs();
                    self.crypt_in_place(start_lba + i, &mut bounce[off..off + self.bs()]);
                }
                // Map bounce into a VirtAddr to reuse inner.submit_request path
                let va = VirtAddr::new(bounce.as_ptr() as u64);
                let res = self.inner.submit_request(IoRequest {
                    buffer: va,
                    buffer_size: byte_len,
                    completion_callback: None,
                    ..request
                });
                // Prevent bounce from being optimized out before write completes
                core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
                res?;
                if let Some(cb) = request.completion_callback.take() {
                    cb(IoResult {
                        status: IoStatus::Success,
                        bytes_transferred: byte_len,
                        error_code: 0,
                        completion_time: crate::time::timestamp_millis(),
                    });
                }
                Ok(())
            }
            IoOperation::Trim | IoOperation::Flush | IoOperation::SecureErase => {
                self.inner.submit_request(IoRequest { completion_callback: None, ..request })
            }
        }
    }

    fn is_ready(&self) -> bool {
        self.inner.is_ready()
    }

    fn statistics(&self) -> &DeviceStatistics {
        &self.stats
    }

    fn read_blocks(&self, start_block: u64, block_count: u32, buffer: &mut [u8]) -> Result<(), IoStatus> {
        let byte_len = block_count as usize * self.bs();
        if buffer.len() < byte_len {
            return Err(IoStatus::InvalidRequest);
        }
        self.inner.read_blocks(start_block, block_count, buffer)?;
        for i in 0..block_count as u64 {
            let off = (i as usize) * self.bs();
            self.crypt_in_place(start_block + i, &mut buffer[off..off + self.bs()]);
        }
        Ok(())
    }

    fn total_sectors(&self) -> u64 {
        self.inner.total_sectors()
    }

    fn maintenance(&self) -> Result<(), &'static str> {
        self.inner.maintenance()
    }

    fn smart_data(&self) -> Option<SmartData> {
        self.inner.smart_data()
    }

    fn secure_erase(&self) -> Result<(), &'static str> {
        self.inner.secure_erase()
    }

    fn set_power_state(&self, state: PowerState) -> Result<(), &'static str> {
        self.inner.set_power_state(state)
    }

    fn supports_secure_erase(&self) -> bool {
        self.inner.supports_secure_erase()
    }

    fn verify_sanitize_completion(&self) -> Result<(), &'static str> {
        self.inner.verify_sanitize_completion()
    }

    fn wait_for_completion(&self, command_id: u16, timeout_ms: u64) -> Result<(), &'static str> {
        self.inner.wait_for_completion(command_id, timeout_ms)
    }

    fn parse_controller_identify(&self, data: &[u8]) -> Result<(), &'static str> {
        self.inner.parse_controller_identify(data)
    }
}
