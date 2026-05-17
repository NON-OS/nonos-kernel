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

use super::supervisor::init_loop;
use crate::sys::boot_log;

pub fn run_init() -> ! {
    boot_log::ok("INIT", "Starting");

    // Under the user-entry proof profile, proof_io is the first
    // CPL=3 binary on the run queue. Its `_start` is two syscalls
    // (MkDebug + MkExit), so a `[proof_io]` line on serial proves
    // SYSCALL/SYSRET end-to-end before any heavier capsule runs.
    #[cfg(feature = "nonos-user-entry-proof")]
    {
        crate::sys::serial::println(b"[INIT-TRACE] before spawn_proof_io_capsule");
        let _ = crate::userspace::capsule_proof_io::spawn_proof_io_capsule();
        crate::sys::serial::println(b"[INIT-TRACE] after spawn_proof_io_capsule");
    }

    crate::sys::serial::println(b"[INIT-TRACE] before spawn_ramfs_capsule");
    spawn_ramfs_capsule();
    crate::sys::serial::println(b"[INIT-TRACE] after spawn_ramfs_capsule");
    #[cfg(feature = "nonos-ramfs-smoketest")]
    {
        for _ in 0..200 {
            crate::sched::yield_now();
        }
        crate::fs::ramfs_capsule::smoketest::run();
    }

    spawn_keyring_capsule();
    spawn_entropy_capsule();
    spawn_crypto_capsule();
    #[cfg(feature = "nonos-capsule-driver-virtio-rng")]
    spawn_driver_virtio_rng_capsule();
    #[cfg(feature = "nonos-capsule-driver-virtio-blk")]
    spawn_driver_virtio_blk_capsule();
    #[cfg(feature = "nonos-capsule-driver-virtio-gpu")]
    spawn_driver_virtio_gpu_capsule();
    #[cfg(feature = "nonos-capsule-driver-virtio-net")]
    spawn_driver_virtio_net_capsule();
    #[cfg(feature = "nonos-capsule-driver-iwlwifi")]
    spawn_driver_iwlwifi_capsule();
    #[cfg(feature = "nonos-capsule-driver-i2c-pci")]
    spawn_driver_i2c_pci_capsule();
    #[cfg(feature = "nonos-capsule-driver-i2c-hid")]
    spawn_driver_i2c_hid_capsule();
    #[cfg(feature = "nonos-capsule-driver-ps2-input")]
    spawn_driver_ps2_input_capsule();
    #[cfg(feature = "nonos-capsule-driver-xhci")]
    spawn_driver_xhci_capsule();
    #[cfg(feature = "nonos-capsule-driver-usb-hid")]
    spawn_driver_usb_hid_capsule();
    #[cfg(feature = "nonos-capsule-driver-usb-msc")]
    spawn_driver_usb_msc_capsule();
    #[cfg(feature = "nonos-capsule-driver-e1000")]
    spawn_driver_e1000_capsule();
    #[cfg(feature = "nonos-capsule-driver-rtl8139")]
    spawn_driver_rtl8139_capsule();
    #[cfg(feature = "nonos-capsule-driver-rtl8169")]
    spawn_driver_rtl8169_capsule();
    #[cfg(feature = "nonos-capsule-driver-ahci")]
    spawn_driver_ahci_capsule();
    #[cfg(feature = "nonos-capsule-driver-hda")]
    spawn_driver_hda_capsule();
    #[cfg(feature = "nonos-capsule-driver-nvme")]
    spawn_driver_nvme_capsule();
    spawn_vfs_capsule();
    #[cfg(feature = "nonos-capsule-net-l2")]
    spawn_net_l2_capsule();
    #[cfg(feature = "nonos-capsule-net-ip")]
    spawn_net_ip_capsule();
    #[cfg(feature = "nonos-capsule-net-udp")]
    spawn_net_udp_capsule();
    #[cfg(feature = "nonos-capsule-net-dhcp")]
    spawn_net_dhcp_capsule();
    #[cfg(feature = "nonos-capsule-input-router")]
    spawn_input_router_capsule();
    #[cfg(feature = "nonos-capsule-compositor")]
    spawn_compositor_capsule();
    #[cfg(feature = "nonos-capsule-wm")]
    spawn_wm_capsule();
    #[cfg(feature = "nonos-capsule-desktop-shell")]
    spawn_desktop_shell_capsule();
    #[cfg(feature = "nonos-capsule-image-codec")]
    spawn_image_codec_capsule();
    #[cfg(feature = "nonos-capsule-clipboard")]
    spawn_clipboard_capsule();
    #[cfg(feature = "nonos-capsule-login")]
    spawn_login_capsule();
    #[cfg(feature = "nonos-capsule-toolkit")]
    spawn_toolkit_capsule();
    #[cfg(feature = "nonos-capsule-about")]
    spawn_about_capsule();
    #[cfg(feature = "nonos-capsule-calculator")]
    spawn_calculator_capsule();
    #[cfg(feature = "nonos-capsule-terminal")]
    spawn_terminal_capsule();
    #[cfg(feature = "nonos-capsule-file-manager")]
    spawn_file_manager_capsule();
    #[cfg(feature = "nonos-capsule-text-editor")]
    spawn_text_editor_capsule();
    #[cfg(feature = "nonos-capsule-settings")]
    spawn_settings_capsule();
    #[cfg(feature = "nonos-capsule-process-manager")]
    spawn_process_manager_capsule();
    #[cfg(all(feature = "nonos-capsule-wallpaper", not(feature = "nonos-wallpaper-smoketest")))]
    spawn_wallpaper_capsule();
    #[cfg(feature = "nonos-capsule-market")]
    spawn_market_capsule();
    #[cfg(feature = "nonos-keyring-smoketest")]
    super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_KEYRING,
        crate::security::keyring_capsule::smoketest::run,
    );
    #[cfg(feature = "nonos-entropy-smoketest")]
    super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_ENTROPY,
        crate::security::entropy_capsule::smoketest::run,
    );
    #[cfg(feature = "nonos-crypto-hash-smoketest")]
    super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_CRYPTO,
        crate::security::crypto_capsule::smoketest::run,
    );
    #[cfg(feature = "nonos-vfs-smoketest")]
    super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_VFS,
        crate::fs::vfs_capsule::smoketest::run,
    );
    #[cfg(feature = "nonos-driver-virtio-rng-smoketest")]
    super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_DRIVER,
        crate::hardware::virtio_rng_capsule::smoketest::run,
    );
    #[cfg(feature = "nonos-market-smoketest")]
    super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_APPS,
        crate::security::market_capsule::smoketest::run,
    );
    #[cfg(feature = "nonos-driver-virtio-blk-smoketest")]
    super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_DRIVER,
        crate::hardware::virtio_blk_capsule::smoketest::run,
    );
    #[cfg(feature = "nonos-driver-virtio-net-smoketest")]
    super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_DRIVER,
        crate::hardware::virtio_net_capsule::smoketest::run,
    );
    #[cfg(feature = "nonos-driver-ps2-input-smoketest")]
    super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_DRIVER,
        crate::hardware::ps2_kbd_capsule::smoketest::run,
    );
    #[cfg(feature = "nonos-driver-xhci-smoketest")]
    super::capsule_boot::run_smoketest(
        crate::services::caps::CAP_DRIVER,
        crate::hardware::xhci_capsule::smoketest::run,
    );

    boot_log::ok("INIT", "Capsules spawned");
    lower_init_priority();
    for _ in 0..100 {
        crate::sched::yield_now();
    }
    // Replaces the init image with a one-shot proof binary and
    // transfers to CPL=3; control does not return here on
    // success. The wallpaper smoke profile swaps out the binary
    // for the graphics-syscall round trip; production builds
    // launch proof_io.
    #[cfg(feature = "nonos-wallpaper-smoketest")]
    crate::userspace::capsule_wallpaper::launch();
    #[cfg(not(feature = "nonos-wallpaper-smoketest"))]
    crate::userspace::capsule_proof_io::launch();
    init_loop()
}

fn lower_init_priority() {
    use crate::process::core::{Priority, CURRENT_PID, PROCESS_TABLE};
    use core::sync::atomic::Ordering;
    let pid = CURRENT_PID.load(Ordering::Relaxed);
    if let Some(pcb) = PROCESS_TABLE.find_by_pid(pid) {
        *pcb.priority.lock() = Priority::Low;
    }
}

fn spawn_ramfs_capsule() {
    use crate::fs::ramfs_capsule;
    super::capsule_boot::boot(
        "RAMFS",
        "ramfs",
        ramfs_capsule::spawn_ramfs_capsule,
        ramfs_capsule::shared_state,
    );
}

fn spawn_keyring_capsule() {
    use crate::security::keyring_capsule;
    super::capsule_boot::boot(
        "KEYRING",
        "keyring",
        keyring_capsule::spawn_keyring_capsule,
        keyring_capsule::shared_state,
    );
}

fn spawn_entropy_capsule() {
    use crate::security::entropy_capsule;
    super::capsule_boot::boot(
        "ENTROPY",
        "entropy",
        entropy_capsule::spawn_entropy_capsule,
        entropy_capsule::shared_state,
    );
}

fn spawn_crypto_capsule() {
    use crate::security::crypto_capsule;
    super::capsule_boot::boot(
        "CRYPTO",
        "crypto",
        crypto_capsule::spawn_crypto_capsule,
        crypto_capsule::shared_state,
    );
}

fn spawn_vfs_capsule() {
    use crate::fs::vfs_capsule;
    super::capsule_boot::boot(
        "VFS",
        "vfs",
        vfs_capsule::spawn_vfs_capsule,
        vfs_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-input-router")]
fn spawn_input_router_capsule() {
    use crate::userspace::capsule_input_router;
    super::capsule_boot::boot(
        "INPUT-ROUTER",
        "input_router",
        capsule_input_router::spawn_input_router_capsule,
        capsule_input_router::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-compositor")]
fn spawn_compositor_capsule() {
    use crate::userspace::capsule_compositor;
    super::capsule_boot::boot(
        "COMPOSITOR",
        "compositor",
        capsule_compositor::spawn_compositor_capsule,
        capsule_compositor::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-desktop-shell")]
fn spawn_desktop_shell_capsule() {
    use crate::userspace::capsule_desktop_shell;
    super::capsule_boot::boot(
        "DESKTOP-SHELL",
        "desktop_shell",
        capsule_desktop_shell::spawn_desktop_shell_capsule,
        capsule_desktop_shell::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-image-codec")]
fn spawn_image_codec_capsule() {
    use crate::userspace::capsule_image_codec;
    super::capsule_boot::boot(
        "IMAGE-CODEC",
        "image_codec",
        capsule_image_codec::spawn_image_codec_capsule,
        capsule_image_codec::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-clipboard")]
fn spawn_clipboard_capsule() {
    use crate::userspace::capsule_clipboard;
    super::capsule_boot::boot(
        "CLIPBOARD",
        "clipboard",
        capsule_clipboard::spawn_clipboard_capsule,
        capsule_clipboard::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-login")]
fn spawn_login_capsule() {
    use crate::userspace::capsule_login;
    super::capsule_boot::boot(
        "LOGIN",
        "login",
        capsule_login::spawn_login_capsule,
        capsule_login::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-wm")]
fn spawn_wm_capsule() {
    use crate::userspace::capsule_wm;
    super::capsule_boot::boot("WM", "wm", capsule_wm::spawn_wm_capsule, capsule_wm::shared_state);
}

#[cfg(feature = "nonos-capsule-toolkit")]
fn spawn_toolkit_capsule() {
    use crate::userspace::capsule_toolkit;
    super::capsule_boot::boot("TOOLKIT", "toolkit", capsule_toolkit::spawn_toolkit_capsule, || {
        Some("toolkit")
    });
}

#[cfg(feature = "nonos-capsule-about")]
fn spawn_about_capsule() {
    use crate::userspace::capsule_about;
    super::capsule_boot::boot(
        "APP-ABOUT",
        "app_about",
        capsule_about::spawn_about_capsule,
        capsule_about::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-calculator")]
fn spawn_calculator_capsule() {
    use crate::userspace::capsule_calculator;
    super::capsule_boot::boot(
        "APP-CALCULATOR",
        "app_calculator",
        capsule_calculator::spawn_calculator_capsule,
        capsule_calculator::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-terminal")]
fn spawn_terminal_capsule() {
    use crate::userspace::capsule_terminal;
    super::capsule_boot::boot(
        "APP-TERMINAL",
        "app_terminal",
        capsule_terminal::spawn_terminal_capsule,
        capsule_terminal::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-file-manager")]
fn spawn_file_manager_capsule() {
    use crate::userspace::capsule_file_manager;
    super::capsule_boot::boot(
        "APP-FILE-MANAGER",
        "app_file_manager",
        capsule_file_manager::spawn_file_manager_capsule,
        capsule_file_manager::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-text-editor")]
fn spawn_text_editor_capsule() {
    use crate::userspace::capsule_text_editor;
    super::capsule_boot::boot(
        "APP-TEXT-EDITOR",
        "app_text_editor",
        capsule_text_editor::spawn_text_editor_capsule,
        capsule_text_editor::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-settings")]
fn spawn_settings_capsule() {
    use crate::userspace::capsule_settings;
    super::capsule_boot::boot(
        "APP-SETTINGS",
        "app_settings",
        capsule_settings::spawn_settings_capsule,
        capsule_settings::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-process-manager")]
fn spawn_process_manager_capsule() {
    use crate::userspace::capsule_process_manager;
    super::capsule_boot::boot(
        "APP-PROCESS-MANAGER",
        "app_process_manager",
        capsule_process_manager::spawn_process_manager_capsule,
        capsule_process_manager::shared_state,
    );
}

#[cfg(all(feature = "nonos-capsule-wallpaper", not(feature = "nonos-wallpaper-smoketest")))]
fn spawn_wallpaper_capsule() {
    use crate::userspace::capsule_wallpaper;
    super::capsule_boot::boot(
        "DISPLAY",
        "display",
        capsule_wallpaper::spawn_wallpaper_capsule,
        || Some("display"),
    );
}

#[cfg(feature = "nonos-capsule-driver-virtio-rng")]
fn spawn_driver_virtio_rng_capsule() {
    use crate::hardware::virtio_rng_capsule;
    super::capsule_boot::boot(
        "DRIVER-VIRTIO-RNG",
        "driver_virtio_rng",
        virtio_rng_capsule::spawn_driver_virtio_rng_capsule,
        virtio_rng_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-market")]
fn spawn_market_capsule() {
    use crate::security::market_capsule;
    super::capsule_boot::boot(
        "MARKET",
        "market",
        market_capsule::spawn_market_capsule,
        market_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-virtio-blk")]
fn spawn_driver_virtio_blk_capsule() {
    use crate::hardware::virtio_blk_capsule;
    super::capsule_boot::boot(
        "DRIVER-VIRTIO-BLK",
        "driver_virtio_blk",
        virtio_blk_capsule::spawn_driver_virtio_blk_capsule,
        virtio_blk_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-virtio-gpu")]
fn spawn_driver_virtio_gpu_capsule() {
    use crate::hardware::virtio_gpu_capsule;
    super::capsule_boot::boot(
        "DRIVER-VIRTIO-GPU",
        "driver_virtio_gpu",
        virtio_gpu_capsule::spawn_driver_virtio_gpu_capsule,
        virtio_gpu_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-virtio-net")]
fn spawn_driver_virtio_net_capsule() {
    use crate::hardware::virtio_net_capsule;
    super::capsule_boot::boot(
        "DRIVER-VIRTIO-NET",
        "driver_virtio_net",
        virtio_net_capsule::spawn_driver_virtio_net_capsule,
        virtio_net_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-iwlwifi")]
fn spawn_driver_iwlwifi_capsule() {
    use crate::hardware::iwlwifi_capsule;
    super::capsule_boot::boot(
        "DRIVER-IWLWIFI",
        "driver_iwlwifi",
        iwlwifi_capsule::spawn_driver_iwlwifi_capsule,
        iwlwifi_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-i2c-pci")]
fn spawn_driver_i2c_pci_capsule() {
    use crate::hardware::i2c_pci_capsule;
    super::capsule_boot::boot(
        "DRIVER-I2C-PCI",
        "driver_i2c_pci",
        i2c_pci_capsule::spawn_driver_i2c_pci_capsule,
        i2c_pci_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-i2c-hid")]
fn spawn_driver_i2c_hid_capsule() {
    use crate::userspace::capsule_driver_i2c_hid;
    super::capsule_boot::boot(
        "DRIVER-I2C-HID",
        "driver_i2c_hid",
        capsule_driver_i2c_hid::spawn_driver_i2c_hid_capsule,
        capsule_driver_i2c_hid::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-ps2-input")]
fn spawn_driver_ps2_input_capsule() {
    use crate::hardware::ps2_kbd_capsule;
    super::capsule_boot::boot(
        "DRIVER-PS2-INPUT",
        "driver_ps2_input",
        ps2_kbd_capsule::spawn_driver_ps2_input_capsule,
        ps2_kbd_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-xhci")]
fn spawn_driver_xhci_capsule() {
    use crate::hardware::xhci_capsule;
    super::capsule_boot::boot(
        "DRIVER-XHCI",
        "driver_xhci",
        xhci_capsule::spawn_driver_xhci_capsule,
        xhci_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-usb-hid")]
fn spawn_driver_usb_hid_capsule() {
    use crate::userspace::capsule_driver_usb_hid;
    super::capsule_boot::boot(
        "DRIVER-USB-HID",
        "driver_usb_hid",
        capsule_driver_usb_hid::spawn_driver_usb_hid_capsule,
        capsule_driver_usb_hid::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-usb-msc")]
fn spawn_driver_usb_msc_capsule() {
    use crate::userspace::capsule_driver_usb_msc;
    super::capsule_boot::boot(
        "DRIVER-USB-MSC",
        "driver_usb_msc",
        capsule_driver_usb_msc::spawn_driver_usb_msc_capsule,
        capsule_driver_usb_msc::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-e1000")]
fn spawn_driver_e1000_capsule() {
    use crate::hardware::e1000_capsule;
    super::capsule_boot::boot(
        "DRIVER-E1000",
        "driver_e1000",
        e1000_capsule::spawn_driver_e1000_capsule,
        e1000_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-rtl8139")]
fn spawn_driver_rtl8139_capsule() {
    use crate::hardware::rtl8139_capsule;
    super::capsule_boot::boot(
        "DRIVER-RTL8139",
        "driver_rtl8139",
        rtl8139_capsule::spawn_driver_rtl8139_capsule,
        rtl8139_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-rtl8169")]
fn spawn_driver_rtl8169_capsule() {
    use crate::hardware::rtl8169_capsule;
    super::capsule_boot::boot(
        "DRIVER-RTL8169",
        "driver_rtl8169",
        rtl8169_capsule::spawn_driver_rtl8169_capsule,
        rtl8169_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-ahci")]
fn spawn_driver_ahci_capsule() {
    use crate::hardware::ahci_capsule;
    super::capsule_boot::boot(
        "DRIVER-AHCI",
        "driver_ahci",
        ahci_capsule::spawn_driver_ahci_capsule,
        ahci_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-hda")]
fn spawn_driver_hda_capsule() {
    use crate::hardware::hda_capsule;
    super::capsule_boot::boot(
        "DRIVER-HDA",
        "driver_hda",
        hda_capsule::spawn_driver_hda_capsule,
        hda_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-driver-nvme")]
fn spawn_driver_nvme_capsule() {
    use crate::hardware::nvme_capsule;
    super::capsule_boot::boot(
        "DRIVER-NVME",
        "driver_nvme",
        nvme_capsule::spawn_driver_nvme_capsule,
        nvme_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-net-l2")]
fn spawn_net_l2_capsule() {
    use crate::userspace::capsule_net_l2 as l2_capsule;
    super::capsule_boot::boot(
        "NET-L2",
        "net_l2",
        l2_capsule::spawn_net_l2_capsule,
        l2_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-net-ip")]
fn spawn_net_ip_capsule() {
    use crate::userspace::capsule_net_ip as ip_capsule;
    super::capsule_boot::boot(
        "NET-IP",
        "net_ip",
        ip_capsule::spawn_net_ip_capsule,
        ip_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-net-udp")]
fn spawn_net_udp_capsule() {
    use crate::userspace::capsule_net_udp as udp_capsule;
    super::capsule_boot::boot(
        "NET-UDP",
        "net_udp",
        udp_capsule::spawn_net_udp_capsule,
        udp_capsule::shared_state,
    );
}

#[cfg(feature = "nonos-capsule-net-dhcp")]
fn spawn_net_dhcp_capsule() {
    use crate::userspace::capsule_net_dhcp as dhcp_capsule;
    super::capsule_boot::boot(
        "NET-DHCP",
        "net_dhcp",
        dhcp_capsule::spawn_net_dhcp_capsule,
        dhcp_capsule::shared_state,
    );
}
