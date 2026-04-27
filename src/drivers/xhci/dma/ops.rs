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

use super::super::error::{XhciError, XhciResult};
use super::region::DmaRegion;
use core::ptr;

impl DmaRegion {
    pub fn validate_offset(&self, offset: usize, len: usize) -> XhciResult<()> {
        let end = offset.checked_add(len).ok_or(XhciError::TransferLengthOverflow)?;
        if end > self.size {
            return Err(XhciError::BufferSizeMismatch {
                expected: len,
                actual: self.size.saturating_sub(offset),
            });
        }
        Ok(())
    }

    pub fn ptr_at<T>(&self, offset: usize) -> XhciResult<*mut T> {
        self.validate_offset(offset, core::mem::size_of::<T>())?;
        Ok(unsafe { (self.va.as_ptr::<u8>() as *mut u8).add(offset) as *mut T })
    }

    pub fn phys_at(&self, offset: usize) -> XhciResult<u64> {
        if offset >= self.size {
            return Err(XhciError::BufferSizeMismatch { expected: 1, actual: 0 });
        }
        Ok(self.pa.as_u64() + offset as u64)
    }

    pub fn clear(&self) {
        unsafe {
            ptr::write_bytes(self.va.as_mut_ptr::<u8>(), 0, self.size);
        }
    }

    pub fn clear_range(&self, offset: usize, len: usize) -> XhciResult<()> {
        self.validate_offset(offset, len)?;
        unsafe {
            ptr::write_bytes((self.va.as_ptr::<u8>() as *mut u8).add(offset), 0, len);
        }
        Ok(())
    }

    pub fn copy_from(&self, offset: usize, data: &[u8]) -> XhciResult<()> {
        self.validate_offset(offset, data.len())?;
        unsafe {
            ptr::copy_nonoverlapping(
                data.as_ptr(),
                (self.va.as_ptr::<u8>() as *mut u8).add(offset),
                data.len(),
            );
        }
        Ok(())
    }

    pub fn copy_to(&self, offset: usize, data: &mut [u8]) -> XhciResult<()> {
        self.validate_offset(offset, data.len())?;
        unsafe {
            ptr::copy_nonoverlapping(
                self.va.as_ptr::<u8>().add(offset),
                data.as_mut_ptr(),
                data.len(),
            );
        }
        Ok(())
    }

    pub fn read<T: Copy>(&self, offset: usize) -> XhciResult<T> {
        self.validate_offset(offset, core::mem::size_of::<T>())?;
        unsafe { Ok(ptr::read_volatile(self.va.as_ptr::<u8>().add(offset) as *const T)) }
    }

    pub fn write<T: Copy>(&self, offset: usize, value: T) -> XhciResult<()> {
        self.validate_offset(offset, core::mem::size_of::<T>())?;
        unsafe {
            ptr::write_volatile((self.va.as_ptr::<u8>() as *mut u8).add(offset) as *mut T, value);
        }
        Ok(())
    }

    pub unsafe fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.va.as_ptr::<u8>(), self.size) }
    }
    pub unsafe fn as_slice_mut(&self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.va.as_mut_ptr::<u8>(), self.size) }
    }
}
