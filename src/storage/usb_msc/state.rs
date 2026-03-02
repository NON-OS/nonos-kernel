// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.


use core::ptr::addr_of;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use super::types::MscDevice;
use super::constants::MAX_MSC_DEVICES;

pub(super) static mut MSC_DEVICES: [MscDevice; MAX_MSC_DEVICES] = [MscDevice::empty(); MAX_MSC_DEVICES];

pub(super) static MSC_DEVICE_COUNT: AtomicU8 = AtomicU8::new(0);

pub(super) static MSC_INIT: AtomicBool = AtomicBool::new(false);

pub(super) static TAG_COUNTER: AtomicU32 = AtomicU32::new(1);

pub(super) fn next_tag() -> u32 {
    TAG_COUNTER.fetch_add(1, Ordering::SeqCst)
}

pub fn device_count() -> usize {
    MSC_DEVICE_COUNT.load(Ordering::Relaxed) as usize
}

pub fn is_init() -> bool {
    MSC_INIT.load(Ordering::Relaxed)
}

pub fn get_device_info(device_id: u8) -> Option<(u32, u64)> {
    // SAFETY: Read-only access to static device array
    let dev = unsafe { (*addr_of!(MSC_DEVICES)).get(device_id as usize)? };
    if dev.present {
        Some((dev.block_size, dev.total_blocks))
    } else {
        None
    }
}
