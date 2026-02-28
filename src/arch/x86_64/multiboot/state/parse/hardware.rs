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

use x86_64::PhysAddr;

use crate::arch::x86_64::multiboot::error::MultibootError;
use crate::arch::x86_64::multiboot::framebuffer::{ColorInfo, FramebufferInfo, FramebufferType};
use crate::arch::x86_64::multiboot::modules::{BiosBootDevice, VbeInfo};
use crate::arch::x86_64::multiboot::state::types::MultibootManager;

impl MultibootManager {
    pub(in crate::arch::x86_64::multiboot::state) unsafe fn parse_boot_device(
        &self,
        tag_ptr: *const u8,
    ) -> Option<BiosBootDevice> {
        // SAFETY: Caller guarantees tag_ptr points to valid boot device tag.
        unsafe {
            #[repr(C)]
            struct BootDeviceTag {
                tag_type: u32,
                size: u32,
                biosdev: u32,
                partition: u32,
                sub_partition: u32,
            }

            let tag = &*(tag_ptr as *const BootDeviceTag);
            Some(BiosBootDevice {
                bios_dev: tag.biosdev,
                partition: tag.partition,
                sub_partition: tag.sub_partition,
            })
        }
    }

    pub(in crate::arch::x86_64::multiboot::state) unsafe fn parse_vbe_info(
        &self,
        tag_ptr: *const u8,
        size: u32,
    ) -> Option<VbeInfo> {
        // SAFETY: Caller guarantees tag_ptr points to valid VBE info tag.
        unsafe {
            if size < 8 + 8 + 512 + 256 {
                return None;
            }

            #[repr(C)]
            struct VbeTag {
                tag_type: u32,
                size: u32,
                vbe_mode: u16,
                vbe_interface_seg: u16,
                vbe_interface_off: u16,
                vbe_interface_len: u16,
                vbe_control_info: [u8; 512],
                vbe_mode_info: [u8; 256],
            }

            let tag = &*(tag_ptr as *const VbeTag);
            Some(VbeInfo {
                mode: tag.vbe_mode,
                interface_seg: tag.vbe_interface_seg,
                interface_off: tag.vbe_interface_off,
                interface_len: tag.vbe_interface_len,
                control_info: tag.vbe_control_info,
                mode_info: tag.vbe_mode_info,
            })
        }
    }

    pub(in crate::arch::x86_64::multiboot::state) unsafe fn parse_framebuffer(
        &self,
        tag_ptr: *const u8,
        size: u32,
    ) -> Result<FramebufferInfo, MultibootError> {
        // SAFETY: Caller guarantees tag_ptr points to valid framebuffer tag.
        unsafe {
            #[repr(C)]
            struct FramebufferTag {
                tag_type: u32,
                size: u32,
                framebuffer_addr: u64,
                framebuffer_pitch: u32,
                framebuffer_width: u32,
                framebuffer_height: u32,
                framebuffer_bpp: u8,
                framebuffer_type: u8,
                reserved: u8,
            }

            if size < core::mem::size_of::<FramebufferTag>() as u32 {
                return Err(MultibootError::FramebufferError {
                    reason: "Tag too small",
                });
            }

            let tag = &*(tag_ptr as *const FramebufferTag);

            let fb_type = FramebufferType::from(tag.framebuffer_type);

            let color_info = if fb_type == FramebufferType::DirectRgb && size >= 31 {
                let color_ptr = tag_ptr.add(27);
                Some(ColorInfo {
                    red_position: *color_ptr,
                    red_mask_size: *color_ptr.add(1),
                    green_position: *color_ptr.add(2),
                    green_mask_size: *color_ptr.add(3),
                    blue_position: *color_ptr.add(4),
                    blue_mask_size: *color_ptr.add(5),
                })
            } else {
                None
            };

            Ok(FramebufferInfo {
                addr: PhysAddr::new(tag.framebuffer_addr),
                pitch: tag.framebuffer_pitch,
                width: tag.framebuffer_width,
                height: tag.framebuffer_height,
                bpp: tag.framebuffer_bpp,
                framebuffer_type: fb_type,
                color_info,
            })
        }
    }
}
