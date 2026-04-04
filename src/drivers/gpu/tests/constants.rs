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

use crate::drivers::gpu::constants::*;

#[test]
fn test_vendor_qemu() {
    assert_eq!(VENDOR_QEMU, 0x1234);
}

#[test]
fn test_device_std_vga() {
    assert_eq!(DEVICE_STD_VGA, 0x1111);
}

#[test]
fn test_class_display() {
    assert_eq!(CLASS_DISPLAY, 0x03);
}

#[test]
fn test_vbe_index_port() {
    assert_eq!(VBE_INDEX_PORT, 0x1CE);
}

#[test]
fn test_vbe_data_port() {
    assert_eq!(VBE_DATA_PORT, 0x1CF);
}

#[test]
fn test_vbe_dispi_index_id() {
    assert_eq!(VBE_DISPI_INDEX_ID, 0x0);
}

#[test]
fn test_vbe_dispi_index_xres() {
    assert_eq!(VBE_DISPI_INDEX_XRES, 0x1);
}

#[test]
fn test_vbe_dispi_index_yres() {
    assert_eq!(VBE_DISPI_INDEX_YRES, 0x2);
}

#[test]
fn test_vbe_dispi_index_bpp() {
    assert_eq!(VBE_DISPI_INDEX_BPP, 0x3);
}

#[test]
fn test_vbe_dispi_index_enable() {
    assert_eq!(VBE_DISPI_INDEX_ENABLE, 0x4);
}

#[test]
fn test_vbe_dispi_index_bank() {
    assert_eq!(VBE_DISPI_INDEX_BANK, 0x5);
}

#[test]
fn test_vbe_dispi_index_virt_width() {
    assert_eq!(VBE_DISPI_INDEX_VIRT_WIDTH, 0x6);
}

#[test]
fn test_vbe_dispi_index_virt_height() {
    assert_eq!(VBE_DISPI_INDEX_VIRT_HEIGHT, 0x7);
}

#[test]
fn test_vbe_dispi_index_x_offset() {
    assert_eq!(VBE_DISPI_INDEX_X_OFFSET, 0x8);
}

#[test]
fn test_vbe_dispi_index_y_offset() {
    assert_eq!(VBE_DISPI_INDEX_Y_OFFSET, 0x9);
}

#[test]
fn test_vbe_dispi_enabled() {
    assert_eq!(VBE_DISPI_ENABLED, 0x01);
}

#[test]
fn test_vbe_dispi_lfb_enabled() {
    assert_eq!(VBE_DISPI_LFB_ENABLED, 0x40);
}

#[test]
fn test_vbe_dispi_noclearmem() {
    assert_eq!(VBE_DISPI_NOCLEARMEM, 0x80);
}

#[test]
fn test_vbe_dispi_id_magic() {
    assert_eq!(VBE_DISPI_ID_MAGIC, 0xB0C5);
}

#[test]
fn test_default_width() {
    assert_eq!(DEFAULT_WIDTH, 1024);
}

#[test]
fn test_default_height() {
    assert_eq!(DEFAULT_HEIGHT, 768);
}

#[test]
fn test_default_bpp() {
    assert_eq!(DEFAULT_BPP, 32);
}

#[test]
fn test_pci_command_offset() {
    assert_eq!(PCI_COMMAND_OFFSET, 0x04);
}

#[test]
fn test_pci_cmd_io_enable() {
    assert_eq!(PCI_CMD_IO_ENABLE, 1 << 0);
}

#[test]
fn test_pci_cmd_mem_enable() {
    assert_eq!(PCI_CMD_MEM_ENABLE, 1 << 1);
}

#[test]
fn test_pci_cmd_bus_master() {
    assert_eq!(PCI_CMD_BUS_MASTER, 1 << 2);
}

#[test]
fn test_supported_modes_not_empty() {
    assert!(!SUPPORTED_MODES.is_empty());
}

#[test]
fn test_supported_modes_vga() {
    assert!(SUPPORTED_MODES.contains(&(640, 480)));
}

#[test]
fn test_supported_modes_svga() {
    assert!(SUPPORTED_MODES.contains(&(800, 600)));
}

#[test]
fn test_supported_modes_xga() {
    assert!(SUPPORTED_MODES.contains(&(1024, 768)));
}

#[test]
fn test_supported_modes_720p() {
    assert!(SUPPORTED_MODES.contains(&(1280, 720)));
}

#[test]
fn test_supported_modes_sxga() {
    assert!(SUPPORTED_MODES.contains(&(1280, 1024)));
}

#[test]
fn test_supported_modes_1080p() {
    assert!(SUPPORTED_MODES.contains(&(1920, 1080)));
}

#[test]
fn test_min_width() {
    assert_eq!(MIN_WIDTH, 320);
}

#[test]
fn test_min_height() {
    assert_eq!(MIN_HEIGHT, 200);
}

#[test]
fn test_max_width() {
    assert_eq!(MAX_WIDTH, 4096);
}

#[test]
fn test_max_height() {
    assert_eq!(MAX_HEIGHT, 3072);
}

#[test]
fn test_default_within_bounds() {
    assert!(DEFAULT_WIDTH >= MIN_WIDTH);
    assert!(DEFAULT_WIDTH <= MAX_WIDTH);
    assert!(DEFAULT_HEIGHT >= MIN_HEIGHT);
    assert!(DEFAULT_HEIGHT <= MAX_HEIGHT);
}

#[test]
fn test_vbe_dispi_index_sequential() {
    assert_eq!(VBE_DISPI_INDEX_XRES, VBE_DISPI_INDEX_ID + 1);
    assert_eq!(VBE_DISPI_INDEX_YRES, VBE_DISPI_INDEX_XRES + 1);
    assert_eq!(VBE_DISPI_INDEX_BPP, VBE_DISPI_INDEX_YRES + 1);
    assert_eq!(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_INDEX_BPP + 1);
}

#[test]
fn test_vbe_ports_adjacent() {
    assert_eq!(VBE_DATA_PORT, VBE_INDEX_PORT + 1);
}

#[test]
fn test_pci_cmd_bits_distinct() {
    assert_eq!(PCI_CMD_IO_ENABLE & PCI_CMD_MEM_ENABLE, 0);
    assert_eq!(PCI_CMD_MEM_ENABLE & PCI_CMD_BUS_MASTER, 0);
    assert_eq!(PCI_CMD_IO_ENABLE & PCI_CMD_BUS_MASTER, 0);
}
