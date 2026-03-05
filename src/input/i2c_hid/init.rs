// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! I2C HID touchpad initialization.
//!
//! This module handles detection and initialization of I2C HID touchpads.
//! It scans I2C buses for known touchpad addresses and initializes any found devices.

use super::device::{HidDeviceType, I2cHidDevice};
use super::state;

/// Known I2C addresses for touchpads from various manufacturers
const TOUCHPAD_ADDRESSES: &[u8] = &[
    0x15, // ELAN
    0x2C, // Synaptics
    0x10, // HP/Generic
    0x20, // Various
    0x24, // Various
    0x38, // Atmel
    0x4B, // Cypress
    0x4C, // Cypress
    0x34, // Various
    0x5C, // Various
    0x5D, // Goodix
];

/// Initialize the I2C HID subsystem.
///
/// This function:
/// 1. Initializes I2C controllers
/// 2. Scans for HID devices
/// 3. Initializes any touchpads found
/// 4. Sets TOUCHPAD_AVAILABLE flag
///
/// Returns the number of touchpads found.
pub fn init() -> usize {
    // First, enable touchpad availability so cursor appears even if detection fails
    state::set_available(true);

    // Ensure cursor is at a visible position (center of default screen)
    let (w, h) = state::get_screen_size();
    state::set_cursor(w / 2, h / 2);

    crate::log::info!("i2c_hid: init() called, cursor at ({}, {})", w/2, h/2);

    // Initialize I2C controllers
    let controller_count = crate::drivers::i2c::pci::init();
    crate::log::info!("i2c_hid: {} I2C controller(s) found", controller_count);

    if controller_count == 0 {
        crate::log::info!("i2c_hid: No I2C controllers - cursor will not respond to touch");
        return 0;
    }

    // Try automatic detection first
    let mut touchpad_count = detect_hid_devices();

    // If automatic detection failed, probe known addresses
    if touchpad_count == 0 {
        crate::log::info!("i2c_hid: Auto-detection failed, probing known addresses...");
        touchpad_count = probe_known_addresses(controller_count);
    }

    if touchpad_count > 0 {
        crate::log::info!("i2c_hid: {} touchpad(s) initialized successfully", touchpad_count);
    } else {
        crate::log::info!("i2c_hid: No touchpads found - cursor will not respond to touch");
    }

    touchpad_count
}

/// Detect HID devices using the I2C driver's detection mechanism
fn detect_hid_devices() -> usize {
    let detected = crate::drivers::i2c::pci::detect_hid_devices();
    let mut count = 0;

    for (controller_idx, address) in detected {
        if try_init_touchpad(controller_idx, address) {
            count += 1;
        }
    }

    count
}

/// Probe all known touchpad addresses on all controllers
fn probe_known_addresses(controller_count: usize) -> usize {
    for controller_idx in 0..controller_count {
        for &address in TOUCHPAD_ADDRESSES {
            if try_init_touchpad(controller_idx, address) {
                // Found a touchpad - one is usually enough
                return 1;
            }
        }
    }
    0
}

/// Try to initialize a touchpad at the given controller/address
fn try_init_touchpad(controller: usize, address: u8) -> bool {
    // Try to create the device
    let mut device = match I2cHidDevice::new(controller, address) {
        Ok(dev) => dev,
        Err(_) => return false,
    };

    // Try to initialize it
    if device.init().is_err() {
        return false;
    }

    // Check if it's a touchpad or mouse
    let device_type = device.device_type();
    if !matches!(device_type, HidDeviceType::Touchpad | HidDeviceType::Mouse) {
        return false;
    }

    // Log successful detection
    let hid_desc = device.hid_descriptor();
    let report_desc = device.report_descriptor();
    crate::log::info!(
        "i2c_hid: Touchpad found - VID:0x{:04X} PID:0x{:04X}",
        hid_desc.vendor_id,
        hid_desc.product_id
    );
    crate::log::info!(
        "i2c_hid: Resolution: {}x{}, Max contacts: {}",
        report_desc.logical_max_x,
        report_desc.logical_max_y,
        report_desc.max_contact_count
    );

    // Add to device list
    state::add_device(device);

    true
}
