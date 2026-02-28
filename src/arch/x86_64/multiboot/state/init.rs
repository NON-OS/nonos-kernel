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

use core::sync::atomic::Ordering;
use x86_64::VirtAddr;

use super::types::MultibootManager;
use super::super::constants::MULTIBOOT2_BOOTLOADER_MAGIC;
use super::super::error::MultibootError;
use super::super::platform::detect_platform;
use super::util::format_bytes;

impl MultibootManager {
    /// # Safety
    /// The info_addr must point to a valid Multiboot2 information structure.
    pub unsafe fn initialize(
        &self,
        magic: u32,
        info_addr: VirtAddr,
    ) -> Result<(), MultibootError> {
        // SAFETY: Caller guarantees info_addr points to valid Multiboot2 structure.
        unsafe {
            if self.initialized.load(Ordering::SeqCst) {
                return Err(MultibootError::AlreadyInitialized);
            }

            if magic != MULTIBOOT2_BOOTLOADER_MAGIC {
                return Err(MultibootError::InvalidMagic {
                    expected: MULTIBOOT2_BOOTLOADER_MAGIC,
                    found: magic,
                });
            }

            self.bootloader_magic.store(magic as u64, Ordering::SeqCst);

            let parsed = self.parse_info(info_addr)?;

            self.stats
                .total_available_memory
                .store(parsed.total_available_memory(), Ordering::SeqCst);
            self.stats
                .total_reserved_memory
                .store(parsed.total_reserved_memory(), Ordering::SeqCst);

            *self.parsed_info.write() = Some(parsed);

            let platform = detect_platform();
            *self.platform.write() = platform;

            self.initialized.store(true, Ordering::SeqCst);

            crate::log::info!(
                "Multiboot2 initialized: {} available, {} reserved, platform: {}",
                format_bytes(self.stats.total_available_memory.load(Ordering::SeqCst)),
                format_bytes(self.stats.total_reserved_memory.load(Ordering::SeqCst)),
                platform.name()
            );

            Ok(())
        }
    }
}
