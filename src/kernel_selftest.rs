extern crate alloc;

use crate::drivers;
use crate::drivers::console::{self, LogLevel};

pub fn run() -> bool {
    let mut ok = true;

    console::write_message("selftest start", LogLevel::Info, "selftest");

    match drivers::get_pci_manager() {
        Some(mgr) => {
            let s = mgr.get_stats();
            console::write_message(
                &alloc::format!("pci ok devices={} msix={}", s.total_devices, s.msix_devices),
                LogLevel::Info,
                "selftest",
            );
        }
        None => {
            console::write_message("pci missing", LogLevel::Error, "selftest");
            ok = false;
        }
    }

    if let Some(cs) = drivers::console::get_console_stats() {
        console::write_message(
            &alloc::format!(
                "console ok serial={} logs={}",
                cs.serial_initialized,
                cs.log_buffer_size
            ),
            LogLevel::Info,
            "selftest",
        );
    }

    if drivers::nonos_keyboard::get_keyboard().is_some() {
        console::write_message("keyboard ok", LogLevel::Info, "selftest");
    }

    if let Some(ahci) = drivers::nonos_ahci::get_controller() {
        let s = ahci.get_stats();
        console::write_message(
            &alloc::format!("ahci ok ports={} r={} w={}", s.devices_count, s.read_ops, s.write_ops),
            LogLevel::Info,
            "selftest",
        );
    }

    if let Some(nvme) = drivers::nonos_nvme::get_controller() {
        let s = nvme.get_stats();
        console::write_message(
            &alloc::format!(
                "nvme ok ns={} br={} bw={}",
                s.namespaces, s.bytes_read, s.bytes_written
            ),
            LogLevel::Info,
            "selftest",
        );
    }

    if let Some(xhci) = drivers::nonos_xhci::get_controller() {
        let s = xhci.get_stats();
        console::write_message(
            &alloc::format!("xhci ok dev={} irq={}", s.devices_connected, s.interrupts),
            LogLevel::Info,
            "selftest",
        );
    }

    if let Some(gpu) = drivers::nonos_gpu::get_driver() {
        let s = gpu.get_stats();
        console::write_message(
            &alloc::format!("gpu ok {:04X}:{:04X} frames={}", s.vendor_id, s.device_id, s.frames_rendered),
            LogLevel::Info,
            "selftest",
        );
    }

    if let Some(audio) = drivers::nonos_audio::get_controller() {
        let s = audio.get_stats();
        console::write_message(
            &alloc::format!("audio ok codecs={} streams={}", s.codecs_detected, s.active_streams),
            LogLevel::Info,
            "selftest",
        );
    }

    if ok {
        console::write_message("SELFTEST PASS", LogLevel::Info, "selftest");
    } else {
        console::write_message("SELFTEST FAIL", LogLevel::Error, "selftest");
    }
    ok
}
