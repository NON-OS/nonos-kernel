// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

static mut HOSTNAME: [u8; 64] = [0; 64];
static mut HOSTNAME_LEN: usize = 5;
static mut DOMAINNAME: [u8; 64] = [0; 64];
static mut DOMAINNAME_LEN: usize = 0;

pub fn init() {
    unsafe {
        HOSTNAME[..5].copy_from_slice(b"nonos");
        HOSTNAME_LEN = 5;
    }
}

pub fn get() -> &'static str {
    unsafe {
        if HOSTNAME_LEN == 0 {
            "nonos"
        } else {
            core::str::from_utf8_unchecked(&HOSTNAME[..HOSTNAME_LEN])
        }
    }
}

pub fn set(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("Hostname cannot be empty");
    }
    if name.len() > 63 {
        return Err("Hostname too long");
    }
    if !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.') {
        return Err("Invalid hostname characters");
    }

    unsafe {
        HOSTNAME[..name.len()].copy_from_slice(name.as_bytes());
        HOSTNAME_LEN = name.len();
    }
    Ok(())
}

pub fn get_domain() -> &'static str {
    unsafe {
        if DOMAINNAME_LEN == 0 {
            ""
        } else {
            core::str::from_utf8_unchecked(&DOMAINNAME[..DOMAINNAME_LEN])
        }
    }
}

pub fn set_domain(name: &str) -> Result<(), &'static str> {
    if name.len() > 63 {
        return Err("Domainname too long");
    }

    unsafe {
        if name.is_empty() {
            DOMAINNAME_LEN = 0;
        } else {
            DOMAINNAME[..name.len()].copy_from_slice(name.as_bytes());
            DOMAINNAME_LEN = name.len();
        }
    }
    Ok(())
}
