// Module-level attributes removed - no_std is set at crate level

//! User-pointer validation and safe copy helpers.

use core::ptr;

#[cfg(target_arch = "x86_64")]
use x86_64::VirtAddr;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Access { Read, Write }

#[cfg(target_arch = "x86_64")]
const KERNEL_BASE: u64 = 0xFFFF_8000_0000_0000;
#[cfg(target_arch = "x86_64")]
const USER_MAX: u64 = KERNEL_BASE - 1;

pub const MAX_GUARDED_COPY: usize = 8 * 1024 * 1024;

#[inline] pub fn is_nonnull(p: u64) -> bool { p != 0 }
#[inline] pub fn is_reasonable_len(n: u64, max: usize) -> bool { n != 0 && (n as usize) <= max }

#[inline]
pub fn is_canonical(addr: u64) -> bool {
    #[cfg(target_arch = "x86_64")] { 
        let sign_bits = addr >> 47;
        sign_bits == 0 || sign_bits == 0x1FFFF 
    }
    #[cfg(not(target_arch = "x86_64"))] { true }
}

#[inline]
pub fn in_user_range(addr: u64, len: usize) -> bool {
    if addr == 0 || len == 0 { return false; }
    if !is_canonical(addr) { return false; }
    let end = match addr.checked_add(len as u64) { Some(v) => v, None => return false };
    #[cfg(target_arch = "x86_64")] { end - 1 <= USER_MAX }
    #[cfg(not(target_arch = "x86_64"))] { true }
}

pub fn validate_user_region(addr: u64, len: usize, _access: Access) -> Result<(), &'static str> {
    if !in_user_range(addr, len) { return Err("EFAULT"); }
    Ok(())
}

pub fn copy_from_user(dst: &mut [u8], user_src: u64) -> Result<usize, &'static str> {
    let len = dst.len();
    if len == 0 { return Ok(0); }
    if len > MAX_GUARDED_COPY { return Err("EINVAL"); }
    validate_user_region(user_src, len, Access::Read)?;
    unsafe { ptr::copy_nonoverlapping(user_src as *const u8, dst.as_mut_ptr(), len); }
    Ok(len)
}

pub fn copy_to_user(user_dst: u64, src: &[u8]) -> Result<usize, &'static str> {
    let len = src.len();
    if len == 0 { return Ok(0); }
    if len > MAX_GUARDED_COPY { return Err("EINVAL"); }
    validate_user_region(user_dst, len, Access::Write)?;
    unsafe { ptr::copy_nonoverlapping(src.as_ptr(), user_dst as *mut u8, len); }
    Ok(len)
}

pub fn read_cstr_from_user(mut addr: u64, max_len: usize) -> Result<alloc::string::String, &'static str> {
    extern crate alloc;
    use alloc::{string::String, vec::Vec};

    if max_len == 0 || max_len > MAX_GUARDED_COPY { return Err("EINVAL"); }
    if !in_user_range(addr, 1) { return Err("EFAULT"); }

    let mut buf = Vec::with_capacity(max_len.min(64));
    for _ in 0..max_len {
        let b = unsafe { ptr::read(addr as *const u8) };
        if b == 0 {
            let s = core::str::from_utf8(&buf).map_err(|_| "EINVAL")?;
            return Ok(String::from(s));
        }
        buf.push(b);
        addr = addr.checked_add(1).ok_or("EFAULT")?;
        if !is_canonical(addr) { return Err("EFAULT"); }
    }
    Err("ENAMETOOLONG")
}

pub unsafe fn user_slice_mut<'a>(addr: u64, len: usize) -> Result<&'a mut [u8], &'static str> {
    validate_user_region(addr, len, Access::Write)?;
    Ok(core::slice::from_raw_parts_mut(addr as *mut u8, len))
}

pub unsafe fn user_slice<'a>(addr: u64, len: usize) -> Result<&'a [u8], &'static str> {
    validate_user_region(addr, len, Access::Read)?;
    Ok(core::slice::from_raw_parts(addr as *const u8, len))
}
