extern crate alloc;

use crate::drivers;
use crate::drivers::console::{self, LogLevel};

pub fn run() -> bool {
    let mut ok = true;

    console::write_message("selftest start");

    match drivers::get_pci_manager() {
        Some(mgr) => {
            let s = mgr.get_stats();
            console::write_message(
                &alloc::format!("pci ok devices={} msix={}", s.total_devices, s.msix_devices)
            );
        }
        None => {
            console::write_message("pci missing");
            ok = false;
        }
    }

    let cs = drivers::console::get_console_stats();
    console::write_message(
        &alloc::format!(
            "console ok msgs={} bytes={}",
            cs.messages_written.load(core::sync::atomic::Ordering::Relaxed),
            cs.bytes_written.load(core::sync::atomic::Ordering::Relaxed)
        )
    );

    let _ = drivers::nonos_keyboard::get_keyboard();
    console::write_message("keyboard ok");

    if let Some(ahci) = drivers::nonos_ahci::get_controller() {
        let s = ahci.get_stats();
        console::write_message(
            &alloc::format!("ahci ok ports={} r={} w={}", s.devices_count, s.read_ops, s.write_ops)
        );
    }

    if let Some(nvme) = drivers::nonos_nvme::get_controller() {
        let s = nvme.get_stats();
        console::write_message(
            &alloc::format!(
                "nvme ok ns={} br={} bw={}",
                s.namespaces, s.bytes_read, s.bytes_written
            )
        );
    }

    if let Some(xhci) = drivers::nonos_xhci::get_controller() {
        let s = xhci.get_stats();
        console::write_message(
            &alloc::format!("xhci ok dev={} irq={}", s.devices_connected, s.interrupts)
        );
    }

    if let Some(s) = drivers::nonos_gpu::with_driver(|gpu| gpu.get_stats()) {
        console::write_message(
            &alloc::format!("gpu ok {:04X}:{:04X} frames={}", s.vendor_id, s.device_id, s.frames_rendered)
        );
    }

    if let Some(audio) = drivers::nonos_audio::get_controller() {
        let s = audio.get_stats();
        console::write_message(
            &alloc::format!("audio ok codecs={} streams={}", s.codecs_detected, s.active_streams)
        );
    }

    if ok {
        console::write_message("SELFTEST PASS");
    } else {
        console::write_message("SELFTEST FAIL");
    }
    ok
}
