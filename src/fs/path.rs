#![no_std]

extern crate alloc;

use alloc::vec::Vec;

pub fn cstr_to_string(ptr: *const u8) -> Result<alloc::string::String, &'static str> {
    if ptr.is_null() {
        return Err("Null pointer");
    }
    let mut bytes: Vec<u8> = Vec::new();
    let mut off = 0usize;
    loop {
        let b = unsafe { core::ptr::read(ptr.add(off)) };
        if b == 0 {
            break;
        }
        bytes.push(b);
        if off > 4096 {
            return Err("Path too long");
        }
        off += 1;
    }
    core::str::from_utf8(&bytes)
        .map(|s| s.to_string())
        .map_err(|_| "Invalid UTF-8 in path")
}
