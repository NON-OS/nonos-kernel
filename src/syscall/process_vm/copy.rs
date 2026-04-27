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

use super::translate::{is_writable_with_cr3, phys_to_virt, translate_with_cr3};
use crate::memory::paging::constants::PAGE_SIZE_4K as PAGE_SIZE;

pub fn copy_from_remote(cr3: u64, remote_addr: usize, local_buf: &mut [u8]) -> Result<usize, i32> {
    let mut copied = 0;
    let mut remote = remote_addr;
    while copied < local_buf.len() {
        let page_offset = remote & (PAGE_SIZE as usize - 1);
        let chunk_size = (PAGE_SIZE as usize - page_offset).min(local_buf.len() - copied);
        let phys = translate_with_cr3(cr3, remote).ok_or(-14i32)?;
        let virt = phys_to_virt(phys);
        unsafe {
            core::ptr::copy_nonoverlapping(
                virt as *const u8,
                local_buf[copied..].as_mut_ptr(),
                chunk_size,
            );
        }
        copied += chunk_size;
        remote += chunk_size;
    }
    Ok(copied)
}

pub fn copy_to_remote(cr3: u64, remote_addr: usize, local_buf: &[u8]) -> Result<usize, i32> {
    let mut copied = 0;
    let mut remote = remote_addr;
    while copied < local_buf.len() {
        let page_offset = remote & (PAGE_SIZE as usize - 1);
        let chunk_size = (PAGE_SIZE as usize - page_offset).min(local_buf.len() - copied);
        if !is_writable_with_cr3(cr3, remote) {
            return Err(-14);
        }
        let phys = translate_with_cr3(cr3, remote).ok_or(-14i32)?;
        let virt = phys_to_virt(phys);
        unsafe {
            core::ptr::copy_nonoverlapping(
                local_buf[copied..].as_ptr(),
                virt as *mut u8,
                chunk_size,
            );
        }
        copied += chunk_size;
        remote += chunk_size;
    }
    Ok(copied)
}

pub fn copy_byte_from_remote(cr3: u64, remote_addr: usize) -> Result<u8, i32> {
    let phys = translate_with_cr3(cr3, remote_addr).ok_or(-14i32)?;
    let virt = phys_to_virt(phys);
    Ok(unsafe { *(virt as *const u8) })
}

pub fn copy_byte_to_remote(cr3: u64, remote_addr: usize, byte: u8) -> Result<(), i32> {
    if !is_writable_with_cr3(cr3, remote_addr) {
        return Err(-14);
    }
    let phys = translate_with_cr3(cr3, remote_addr).ok_or(-14i32)?;
    let virt = phys_to_virt(phys);
    unsafe {
        *(virt as *mut u8) = byte;
    }
    Ok(())
}

pub fn zero_remote(cr3: u64, remote_addr: usize, len: usize) -> Result<usize, i32> {
    let mut zeroed = 0;
    let mut remote = remote_addr;
    while zeroed < len {
        let page_offset = remote & (PAGE_SIZE as usize - 1);
        let chunk_size = (PAGE_SIZE as usize - page_offset).min(len - zeroed);
        if !is_writable_with_cr3(cr3, remote) {
            return Err(-14);
        }
        let phys = translate_with_cr3(cr3, remote).ok_or(-14i32)?;
        let virt = phys_to_virt(phys);
        unsafe {
            core::ptr::write_bytes(virt as *mut u8, 0, chunk_size);
        }
        zeroed += chunk_size;
        remote += chunk_size;
    }
    Ok(zeroed)
}
