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

extern crate alloc;

use alloc::collections::BTreeMap;
use spin::Once;

#[derive(Clone, Copy)]
pub struct BaselineHashes {
    pub elf: [u8; 32],
    pub cert: [u8; 32],
    pub manifest: [u8; 32],
}

static BOOT_BASELINE: Once<BTreeMap<&'static str, BaselineHashes>> = Once::new();

pub fn lookup(name: &str) -> Option<BaselineHashes> {
    BOOT_BASELINE.get().and_then(|m| m.get(name).copied())
}

pub fn init_boot_baseline() {
    blake3_self_test();
    let mut map: BTreeMap<&'static str, BaselineHashes> = BTreeMap::new();
    insert_all(&mut map);
    BOOT_BASELINE.call_once(|| map);
    let count = BOOT_BASELINE.get().map(|m| m.len()).unwrap_or(0);
    crate::sys::boot_log::info(&alloc::format!(
        "[boot_baseline] baked {} verified capsules",
        count,
    ));
}

fn blake3_self_test() {
    let input = [0xAAu8; 1024];
    let got = *blake3::hash(&input).as_bytes();
    let expect: [u8; 32] = [
        0x1d, 0x6a, 0xdb, 0x86, 0xdb, 0xe5, 0x98, 0x90,
        0x37, 0x2b, 0x1a, 0xe6, 0x2d, 0xbc, 0xda, 0x91,
        0x0f, 0x5c, 0x98, 0xa1, 0x71, 0x65, 0x98, 0x6e,
        0x51, 0x7d, 0x24, 0x10, 0x87, 0x2f, 0xd4, 0x35,
    ];
    if got != expect {
        panic!(
            "[boot_baseline] blake3 self-test FAILED: got {:02x?} expected {:02x?}",
            got, expect,
        );
    }
}

fn insert_all(map: &mut BTreeMap<&'static str, BaselineHashes>) {
    #[cfg(feature = "nonos-capsule-ramfs")]
    {
        use crate::fs::ramfs_capsule::embed::{
            RAMFS_ELF,
            RAMFS_MANIFEST_BYTES,
            RAMFS_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "ramfs",
            BaselineHashes {
                elf: hash(RAMFS_ELF),
                cert: hash(RAMFS_NONOS_ID_CERT_BYTES),
                manifest: hash(RAMFS_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-vfs")]
    {
        use crate::fs::vfs_capsule::embed::{
            VFS_ELF,
            VFS_MANIFEST_BYTES,
            VFS_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "vfs_pool",
            BaselineHashes {
                elf: hash(VFS_ELF),
                cert: hash(VFS_NONOS_ID_CERT_BYTES),
                manifest: hash(VFS_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-driver-ahci")]
    {
        use crate::hardware::ahci_capsule::embed::{
            DRIVER_AHCI_ELF,
            DRIVER_AHCI_MANIFEST_BYTES,
            DRIVER_AHCI_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "driver.ahci0",
            BaselineHashes {
                elf: hash(DRIVER_AHCI_ELF),
                cert: hash(DRIVER_AHCI_NONOS_ID_CERT_BYTES),
                manifest: hash(DRIVER_AHCI_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-driver-e1000")]
    {
        use crate::hardware::e1000_capsule::embed::{
            DRIVER_E1000_ELF,
            DRIVER_E1000_MANIFEST_BYTES,
            DRIVER_E1000_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "driver.e1000_0",
            BaselineHashes {
                elf: hash(DRIVER_E1000_ELF),
                cert: hash(DRIVER_E1000_NONOS_ID_CERT_BYTES),
                manifest: hash(DRIVER_E1000_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-driver-hda")]
    {
        use crate::hardware::hda_capsule::embed::{
            DRIVER_HDA_ELF,
            DRIVER_HDA_MANIFEST_BYTES,
            DRIVER_HDA_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "driver.hda0",
            BaselineHashes {
                elf: hash(DRIVER_HDA_ELF),
                cert: hash(DRIVER_HDA_NONOS_ID_CERT_BYTES),
                manifest: hash(DRIVER_HDA_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-driver-i2c-pci")]
    {
        use crate::hardware::i2c_pci_capsule::embed::{
            DRIVER_I2C_PCI_ELF,
            DRIVER_I2C_PCI_MANIFEST_BYTES,
            DRIVER_I2C_PCI_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "driver.i2c_pci0",
            BaselineHashes {
                elf: hash(DRIVER_I2C_PCI_ELF),
                cert: hash(DRIVER_I2C_PCI_NONOS_ID_CERT_BYTES),
                manifest: hash(DRIVER_I2C_PCI_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-driver-iwlwifi")]
    {
        use crate::hardware::iwlwifi_capsule::embed::{
            DRIVER_IWLWIFI_ELF,
            DRIVER_IWLWIFI_MANIFEST_BYTES,
            DRIVER_IWLWIFI_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "driver.iwlwifi0",
            BaselineHashes {
                elf: hash(DRIVER_IWLWIFI_ELF),
                cert: hash(DRIVER_IWLWIFI_NONOS_ID_CERT_BYTES),
                manifest: hash(DRIVER_IWLWIFI_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-driver-nvme")]
    {
        use crate::hardware::nvme_capsule::embed::{
            DRIVER_NVME_ELF,
            DRIVER_NVME_MANIFEST_BYTES,
            DRIVER_NVME_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "driver.nvme0",
            BaselineHashes {
                elf: hash(DRIVER_NVME_ELF),
                cert: hash(DRIVER_NVME_NONOS_ID_CERT_BYTES),
                manifest: hash(DRIVER_NVME_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-driver-ps2-input")]
    {
        use crate::hardware::ps2_kbd_capsule::embed::{
            DRIVER_PS2_INPUT_ELF,
            DRIVER_PS2_INPUT_MANIFEST_BYTES,
            DRIVER_PS2_INPUT_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "driver.ps2_kbd0",
            BaselineHashes {
                elf: hash(DRIVER_PS2_INPUT_ELF),
                cert: hash(DRIVER_PS2_INPUT_NONOS_ID_CERT_BYTES),
                manifest: hash(DRIVER_PS2_INPUT_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-driver-rtl8139")]
    {
        use crate::hardware::rtl8139_capsule::embed::{
            DRIVER_RTL8139_ELF,
            DRIVER_RTL8139_MANIFEST_BYTES,
            DRIVER_RTL8139_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "driver.rtl8139_0",
            BaselineHashes {
                elf: hash(DRIVER_RTL8139_ELF),
                cert: hash(DRIVER_RTL8139_NONOS_ID_CERT_BYTES),
                manifest: hash(DRIVER_RTL8139_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-driver-rtl8169")]
    {
        use crate::hardware::rtl8169_capsule::embed::{
            DRIVER_RTL8169_ELF,
            DRIVER_RTL8169_MANIFEST_BYTES,
            DRIVER_RTL8169_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "driver.rtl8169_0",
            BaselineHashes {
                elf: hash(DRIVER_RTL8169_ELF),
                cert: hash(DRIVER_RTL8169_NONOS_ID_CERT_BYTES),
                manifest: hash(DRIVER_RTL8169_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-driver-virtio-blk")]
    {
        use crate::hardware::virtio_blk_capsule::embed::{
            DRIVER_VIRTIO_BLK_ELF,
            DRIVER_VIRTIO_BLK_MANIFEST_BYTES,
            DRIVER_VIRTIO_BLK_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "driver.virtio_blk0",
            BaselineHashes {
                elf: hash(DRIVER_VIRTIO_BLK_ELF),
                cert: hash(DRIVER_VIRTIO_BLK_NONOS_ID_CERT_BYTES),
                manifest: hash(DRIVER_VIRTIO_BLK_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-driver-virtio-gpu")]
    {
        use crate::hardware::virtio_gpu_capsule::embed::{
            DRIVER_VIRTIO_GPU_ELF,
            DRIVER_VIRTIO_GPU_MANIFEST_BYTES,
            DRIVER_VIRTIO_GPU_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "driver.virtio_gpu0",
            BaselineHashes {
                elf: hash(DRIVER_VIRTIO_GPU_ELF),
                cert: hash(DRIVER_VIRTIO_GPU_NONOS_ID_CERT_BYTES),
                manifest: hash(DRIVER_VIRTIO_GPU_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-driver-virtio-net")]
    {
        use crate::hardware::virtio_net_capsule::embed::{
            DRIVER_VIRTIO_NET_ELF,
            DRIVER_VIRTIO_NET_MANIFEST_BYTES,
            DRIVER_VIRTIO_NET_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "driver.virtio_net0",
            BaselineHashes {
                elf: hash(DRIVER_VIRTIO_NET_ELF),
                cert: hash(DRIVER_VIRTIO_NET_NONOS_ID_CERT_BYTES),
                manifest: hash(DRIVER_VIRTIO_NET_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-driver-virtio-rng")]
    {
        use crate::hardware::virtio_rng_capsule::embed::{
            DRIVER_VIRTIO_RNG_ELF,
            DRIVER_VIRTIO_RNG_MANIFEST_BYTES,
            DRIVER_VIRTIO_RNG_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "driver.virtio_rng",
            BaselineHashes {
                elf: hash(DRIVER_VIRTIO_RNG_ELF),
                cert: hash(DRIVER_VIRTIO_RNG_NONOS_ID_CERT_BYTES),
                manifest: hash(DRIVER_VIRTIO_RNG_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-driver-xhci")]
    {
        use crate::hardware::xhci_capsule::embed::{
            DRIVER_XHCI_ELF,
            DRIVER_XHCI_MANIFEST_BYTES,
            DRIVER_XHCI_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "driver.xhci0",
            BaselineHashes {
                elf: hash(DRIVER_XHCI_ELF),
                cert: hash(DRIVER_XHCI_NONOS_ID_CERT_BYTES),
                manifest: hash(DRIVER_XHCI_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-crypto")]
    {
        use crate::security::crypto_capsule::embed::{
            CRYPTO_ELF,
            CRYPTO_MANIFEST_BYTES,
            CRYPTO_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "crypto_pool",
            BaselineHashes {
                elf: hash(CRYPTO_ELF),
                cert: hash(CRYPTO_NONOS_ID_CERT_BYTES),
                manifest: hash(CRYPTO_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-entropy")]
    {
        use crate::security::entropy_capsule::embed::{
            ENTROPY_ELF,
            ENTROPY_MANIFEST_BYTES,
            ENTROPY_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "entropy_pool",
            BaselineHashes {
                elf: hash(ENTROPY_ELF),
                cert: hash(ENTROPY_NONOS_ID_CERT_BYTES),
                manifest: hash(ENTROPY_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-keyring")]
    {
        use crate::security::keyring_capsule::embed::{
            KEYRING_ELF,
            KEYRING_MANIFEST_BYTES,
            KEYRING_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "keyring",
            BaselineHashes {
                elf: hash(KEYRING_ELF),
                cert: hash(KEYRING_NONOS_ID_CERT_BYTES),
                manifest: hash(KEYRING_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-market")]
    {
        use crate::security::market_capsule::embed::{
            MARKET_ELF,
            MARKET_MANIFEST_BYTES,
            MARKET_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "market.index",
            BaselineHashes {
                elf: hash(MARKET_ELF),
                cert: hash(MARKET_NONOS_ID_CERT_BYTES),
                manifest: hash(MARKET_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-about")]
    {
        use crate::userspace::capsule_about::embed::{
            ABOUT_ELF,
            ABOUT_MANIFEST_BYTES,
            ABOUT_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "app.about",
            BaselineHashes {
                elf: hash(ABOUT_ELF),
                cert: hash(ABOUT_NONOS_ID_CERT_BYTES),
                manifest: hash(ABOUT_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-calculator")]
    {
        use crate::userspace::capsule_calculator::embed::{
            CALCULATOR_ELF,
            CALCULATOR_MANIFEST_BYTES,
            CALCULATOR_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "app.calculator",
            BaselineHashes {
                elf: hash(CALCULATOR_ELF),
                cert: hash(CALCULATOR_NONOS_ID_CERT_BYTES),
                manifest: hash(CALCULATOR_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-clipboard")]
    {
        use crate::userspace::capsule_clipboard::embed::{
            CLIPBOARD_ELF,
            CLIPBOARD_MANIFEST_BYTES,
            CLIPBOARD_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "clipboard",
            BaselineHashes {
                elf: hash(CLIPBOARD_ELF),
                cert: hash(CLIPBOARD_NONOS_ID_CERT_BYTES),
                manifest: hash(CLIPBOARD_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-compositor")]
    {
        use crate::userspace::capsule_compositor::embed::{
            COMPOSITOR_ELF,
            COMPOSITOR_MANIFEST_BYTES,
            COMPOSITOR_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "compositor",
            BaselineHashes {
                elf: hash(COMPOSITOR_ELF),
                cert: hash(COMPOSITOR_NONOS_ID_CERT_BYTES),
                manifest: hash(COMPOSITOR_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-desktop-shell")]
    {
        use crate::userspace::capsule_desktop_shell::embed::{
            DESKTOP_SHELL_ELF,
            DESKTOP_SHELL_MANIFEST_BYTES,
            DESKTOP_SHELL_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "desktop_shell",
            BaselineHashes {
                elf: hash(DESKTOP_SHELL_ELF),
                cert: hash(DESKTOP_SHELL_NONOS_ID_CERT_BYTES),
                manifest: hash(DESKTOP_SHELL_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-driver-i2c-hid")]
    {
        use crate::userspace::capsule_driver_i2c_hid::embed::{
            DRIVER_I2C_HID_ELF,
            DRIVER_I2C_HID_MANIFEST_BYTES,
            DRIVER_I2C_HID_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "driver.i2c_hid0",
            BaselineHashes {
                elf: hash(DRIVER_I2C_HID_ELF),
                cert: hash(DRIVER_I2C_HID_NONOS_ID_CERT_BYTES),
                manifest: hash(DRIVER_I2C_HID_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-driver-usb-hid")]
    {
        use crate::userspace::capsule_driver_usb_hid::embed::{
            DRIVER_USB_HID_ELF,
            DRIVER_USB_HID_MANIFEST_BYTES,
            DRIVER_USB_HID_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "driver.usb_hid0",
            BaselineHashes {
                elf: hash(DRIVER_USB_HID_ELF),
                cert: hash(DRIVER_USB_HID_NONOS_ID_CERT_BYTES),
                manifest: hash(DRIVER_USB_HID_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-driver-usb-msc")]
    {
        use crate::userspace::capsule_driver_usb_msc::embed::{
            DRIVER_USB_MSC_ELF,
            DRIVER_USB_MSC_MANIFEST_BYTES,
            DRIVER_USB_MSC_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "driver.usb_msc0",
            BaselineHashes {
                elf: hash(DRIVER_USB_MSC_ELF),
                cert: hash(DRIVER_USB_MSC_NONOS_ID_CERT_BYTES),
                manifest: hash(DRIVER_USB_MSC_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-file-manager")]
    {
        use crate::userspace::capsule_file_manager::embed::{
            FILE_MANAGER_ELF,
            FILE_MANAGER_MANIFEST_BYTES,
            FILE_MANAGER_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "app.file_manager",
            BaselineHashes {
                elf: hash(FILE_MANAGER_ELF),
                cert: hash(FILE_MANAGER_NONOS_ID_CERT_BYTES),
                manifest: hash(FILE_MANAGER_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-image-codec")]
    {
        use crate::userspace::capsule_image_codec::embed::{
            IMAGE_CODEC_ELF,
            IMAGE_CODEC_MANIFEST_BYTES,
            IMAGE_CODEC_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "image_codec",
            BaselineHashes {
                elf: hash(IMAGE_CODEC_ELF),
                cert: hash(IMAGE_CODEC_NONOS_ID_CERT_BYTES),
                manifest: hash(IMAGE_CODEC_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-input-router")]
    {
        use crate::userspace::capsule_input_router::embed::{
            INPUT_ROUTER_ELF,
            INPUT_ROUTER_MANIFEST_BYTES,
            INPUT_ROUTER_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "input_router",
            BaselineHashes {
                elf: hash(INPUT_ROUTER_ELF),
                cert: hash(INPUT_ROUTER_NONOS_ID_CERT_BYTES),
                manifest: hash(INPUT_ROUTER_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-login")]
    {
        use crate::userspace::capsule_login::embed::{
            LOGIN_ELF,
            LOGIN_MANIFEST_BYTES,
            LOGIN_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "login",
            BaselineHashes {
                elf: hash(LOGIN_ELF),
                cert: hash(LOGIN_NONOS_ID_CERT_BYTES),
                manifest: hash(LOGIN_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-net-dhcp")]
    {
        use crate::userspace::capsule_net_dhcp::embed::{
            NET_DHCP_ELF,
            NET_DHCP_MANIFEST_BYTES,
            NET_DHCP_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "net.dhcp.client",
            BaselineHashes {
                elf: hash(NET_DHCP_ELF),
                cert: hash(NET_DHCP_NONOS_ID_CERT_BYTES),
                manifest: hash(NET_DHCP_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-net-ip")]
    {
        use crate::userspace::capsule_net_ip::embed::{
            NET_IP_ELF,
            NET_IP_MANIFEST_BYTES,
            NET_IP_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "net.ip",
            BaselineHashes {
                elf: hash(NET_IP_ELF),
                cert: hash(NET_IP_NONOS_ID_CERT_BYTES),
                manifest: hash(NET_IP_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-net-l2")]
    {
        use crate::userspace::capsule_net_l2::embed::{
            NET_L2_ELF,
            NET_L2_MANIFEST_BYTES,
            NET_L2_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "net.l2",
            BaselineHashes {
                elf: hash(NET_L2_ELF),
                cert: hash(NET_L2_NONOS_ID_CERT_BYTES),
                manifest: hash(NET_L2_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-net-udp")]
    {
        use crate::userspace::capsule_net_udp::embed::{
            NET_UDP_ELF,
            NET_UDP_MANIFEST_BYTES,
            NET_UDP_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "net.udp",
            BaselineHashes {
                elf: hash(NET_UDP_ELF),
                cert: hash(NET_UDP_NONOS_ID_CERT_BYTES),
                manifest: hash(NET_UDP_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-process-manager")]
    {
        use crate::userspace::capsule_process_manager::embed::{
            PROCESS_MANAGER_ELF,
            PROCESS_MANAGER_MANIFEST_BYTES,
            PROCESS_MANAGER_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "app.process_manager",
            BaselineHashes {
                elf: hash(PROCESS_MANAGER_ELF),
                cert: hash(PROCESS_MANAGER_NONOS_ID_CERT_BYTES),
                manifest: hash(PROCESS_MANAGER_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-proof-io")]
    {
        use crate::userspace::capsule_proof_io::embed::{
            PROOF_IO_ELF,
            PROOF_IO_MANIFEST_BYTES,
            PROOF_IO_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "proof_io",
            BaselineHashes {
                elf: hash(PROOF_IO_ELF),
                cert: hash(PROOF_IO_NONOS_ID_CERT_BYTES),
                manifest: hash(PROOF_IO_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-settings")]
    {
        use crate::userspace::capsule_settings::embed::{
            SETTINGS_ELF,
            SETTINGS_MANIFEST_BYTES,
            SETTINGS_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "app.settings",
            BaselineHashes {
                elf: hash(SETTINGS_ELF),
                cert: hash(SETTINGS_NONOS_ID_CERT_BYTES),
                manifest: hash(SETTINGS_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-terminal")]
    {
        use crate::userspace::capsule_terminal::embed::{
            TERMINAL_ELF,
            TERMINAL_MANIFEST_BYTES,
            TERMINAL_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "app.terminal",
            BaselineHashes {
                elf: hash(TERMINAL_ELF),
                cert: hash(TERMINAL_NONOS_ID_CERT_BYTES),
                manifest: hash(TERMINAL_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-text-editor")]
    {
        use crate::userspace::capsule_text_editor::embed::{
            TEXT_EDITOR_ELF,
            TEXT_EDITOR_MANIFEST_BYTES,
            TEXT_EDITOR_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "app.text_editor",
            BaselineHashes {
                elf: hash(TEXT_EDITOR_ELF),
                cert: hash(TEXT_EDITOR_NONOS_ID_CERT_BYTES),
                manifest: hash(TEXT_EDITOR_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-toolkit")]
    {
        use crate::userspace::capsule_toolkit::embed::{
            TOOLKIT_ELF,
            TOOLKIT_MANIFEST_BYTES,
            TOOLKIT_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "toolkit",
            BaselineHashes {
                elf: hash(TOOLKIT_ELF),
                cert: hash(TOOLKIT_NONOS_ID_CERT_BYTES),
                manifest: hash(TOOLKIT_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-wallpaper")]
    {
        use crate::userspace::capsule_wallpaper::embed::{
            WALLPAPER_ELF,
            WALLPAPER_MANIFEST_BYTES,
            WALLPAPER_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "wallpaper",
            BaselineHashes {
                elf: hash(WALLPAPER_ELF),
                cert: hash(WALLPAPER_NONOS_ID_CERT_BYTES),
                manifest: hash(WALLPAPER_MANIFEST_BYTES),
            },
        );
    }
    #[cfg(feature = "nonos-capsule-wm")]
    {
        use crate::userspace::capsule_wm::embed::{
            WM_ELF,
            WM_MANIFEST_BYTES,
            WM_NONOS_ID_CERT_BYTES,
        };
        map.insert(
            "wm",
            BaselineHashes {
                elf: hash(WM_ELF),
                cert: hash(WM_NONOS_ID_CERT_BYTES),
                manifest: hash(WM_MANIFEST_BYTES),
            },
        );
    }
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}
