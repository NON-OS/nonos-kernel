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

use crate::boot::handoff::types::{FirmwareEntry, FirmwareHandoff, FirmwareType};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

static FIRMWARE_INITIALIZED: AtomicBool = AtomicBool::new(false);
static FIRMWARE_COUNT: AtomicUsize = AtomicUsize::new(0);
static FIRMWARE_PTR: AtomicU64 = AtomicU64::new(0);

pub fn init(handoff: &FirmwareHandoff) {
    if handoff.count > 0 {
        FIRMWARE_PTR.store(handoff as *const FirmwareHandoff as u64, Ordering::SeqCst);
        FIRMWARE_COUNT.store(handoff.count, Ordering::SeqCst);
        FIRMWARE_INITIALIZED.store(true, Ordering::SeqCst);
    }
}

pub fn is_available() -> bool {
    FIRMWARE_INITIALIZED.load(Ordering::Relaxed)
}

pub fn count() -> usize {
    FIRMWARE_COUNT.load(Ordering::Relaxed)
}

fn get_handoff() -> Option<&'static FirmwareHandoff> {
    if !is_available() {
        return None;
    }
    let ptr = FIRMWARE_PTR.load(Ordering::Acquire);
    if ptr == 0 {
        return None;
    }
    unsafe { Some(&*(ptr as *const FirmwareHandoff)) }
}

pub fn get_firmware(fw_type: FirmwareType) -> Option<&'static FirmwareEntry> {
    let handoff = get_handoff()?;
    handoff.get_firmware(fw_type)
}

pub fn get_firmware_data(fw_type: FirmwareType) -> Option<&'static [u8]> {
    let entry = get_firmware(fw_type)?;
    if entry.ptr == 0 || entry.size == 0 {
        return None;
    }
    unsafe { Some(core::slice::from_raw_parts(entry.ptr as *const u8, entry.size as usize)) }
}

pub fn get_intel_wifi_firmware() -> Option<&'static [u8]> {
    let types = [
        FirmwareType::IntelAx210,
        FirmwareType::IntelAx200,
        FirmwareType::Intel9260,
        FirmwareType::Intel8265,
        FirmwareType::Intel7265,
        FirmwareType::IntelAc9560,
        FirmwareType::IntelAc8260,
        FirmwareType::IntelAc7260,
        FirmwareType::IntelAc3168,
        FirmwareType::IntelAc3165,
    ];
    for fw_type in types {
        if let Some(data) = get_firmware_data(fw_type) {
            return Some(data);
        }
    }
    None
}

pub fn get_realtek_wifi_firmware() -> Option<&'static [u8]> {
    let types = [
        FirmwareType::Rtl8852c,
        FirmwareType::Rtl8852b,
        FirmwareType::Rtl8852a,
        FirmwareType::Rtl8851b,
        FirmwareType::Rtl8822c,
        FirmwareType::Rtl8822b,
        FirmwareType::Rtl8821c,
        FirmwareType::Rtl8821a,
        FirmwareType::Rtl8723d,
        FirmwareType::Rtl8723b,
    ];
    for fw_type in types {
        if let Some(data) = get_firmware_data(fw_type) {
            return Some(data);
        }
    }
    None
}

pub fn get_ethernet_firmware() -> Option<&'static [u8]> {
    let types = [
        FirmwareType::IntelI225V,
        FirmwareType::IntelI219V,
        FirmwareType::RealtekRtl8125,
        FirmwareType::RealtekRtl8111,
    ];
    for fw_type in types {
        if let Some(data) = get_firmware_data(fw_type) {
            return Some(data);
        }
    }
    None
}

pub fn get_gpu_firmware() -> Option<&'static [u8]> {
    let types = [
        FirmwareType::AmdGpu,
        FirmwareType::NvidiaGpuRtx3070,
        FirmwareType::NvidiaGpuGtx1060,
        FirmwareType::NvidiaGpuGt1030,
        FirmwareType::IntelGpuIgp,
    ];
    for fw_type in types {
        if let Some(data) = get_firmware_data(fw_type) {
            return Some(data);
        }
    }
    None
}

pub fn list_available() -> alloc::vec::Vec<FirmwareType> {
    let mut result = alloc::vec::Vec::new();
    if let Some(handoff) = get_handoff() {
        for i in 0..handoff.count {
            if handoff.entries[i].ptr != 0 && handoff.entries[i].size > 0 {
                result.push(handoff.entries[i].fw_type);
            }
        }
    }
    result
}
