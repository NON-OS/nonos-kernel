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
use crate::test::framework::TestResult;

pub(crate) fn test_vendor_qemu() -> TestResult {
    if VENDOR_QEMU != 0x1234 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_device_std_vga() -> TestResult {
    if DEVICE_STD_VGA != 0x1111 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_class_display() -> TestResult {
    if CLASS_DISPLAY != 0x03 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vbe_index_port() -> TestResult {
    if VBE_INDEX_PORT != 0x1CE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vbe_data_port() -> TestResult {
    if VBE_DATA_PORT != 0x1CF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vbe_dispi_index_id() -> TestResult {
    if VBE_DISPI_INDEX_ID != 0x0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vbe_dispi_index_xres() -> TestResult {
    if VBE_DISPI_INDEX_XRES != 0x1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vbe_dispi_index_yres() -> TestResult {
    if VBE_DISPI_INDEX_YRES != 0x2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vbe_dispi_index_bpp() -> TestResult {
    if VBE_DISPI_INDEX_BPP != 0x3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vbe_dispi_index_enable() -> TestResult {
    if VBE_DISPI_INDEX_ENABLE != 0x4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vbe_dispi_index_bank() -> TestResult {
    if VBE_DISPI_INDEX_BANK != 0x5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vbe_dispi_index_virt_width() -> TestResult {
    if VBE_DISPI_INDEX_VIRT_WIDTH != 0x6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vbe_dispi_index_virt_height() -> TestResult {
    if VBE_DISPI_INDEX_VIRT_HEIGHT != 0x7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vbe_dispi_index_x_offset() -> TestResult {
    if VBE_DISPI_INDEX_X_OFFSET != 0x8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vbe_dispi_index_y_offset() -> TestResult {
    if VBE_DISPI_INDEX_Y_OFFSET != 0x9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vbe_dispi_enabled() -> TestResult {
    if VBE_DISPI_ENABLED != 0x01 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vbe_dispi_lfb_enabled() -> TestResult {
    if VBE_DISPI_LFB_ENABLED != 0x40 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vbe_dispi_noclearmem() -> TestResult {
    if VBE_DISPI_NOCLEARMEM != 0x80 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vbe_dispi_id_magic() -> TestResult {
    if VBE_DISPI_ID_MAGIC != 0xB0C5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_width() -> TestResult {
    if DEFAULT_WIDTH != 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_height() -> TestResult {
    if DEFAULT_HEIGHT != 768 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_bpp() -> TestResult {
    if DEFAULT_BPP != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_command_offset() -> TestResult {
    if PCI_COMMAND_OFFSET != 0x04 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_cmd_io_enable() -> TestResult {
    if PCI_CMD_IO_ENABLE != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_cmd_mem_enable() -> TestResult {
    if PCI_CMD_MEM_ENABLE != 1 << 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_cmd_bus_master() -> TestResult {
    if PCI_CMD_BUS_MASTER != 1 << 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supported_modes_not_empty() -> TestResult {
    if SUPPORTED_MODES.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supported_modes_vga() -> TestResult {
    if !SUPPORTED_MODES.contains(&(640, 480)) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supported_modes_svga() -> TestResult {
    if !SUPPORTED_MODES.contains(&(800, 600)) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supported_modes_xga() -> TestResult {
    if !SUPPORTED_MODES.contains(&(1024, 768)) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supported_modes_720p() -> TestResult {
    if !SUPPORTED_MODES.contains(&(1280, 720)) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supported_modes_sxga() -> TestResult {
    if !SUPPORTED_MODES.contains(&(1280, 1024)) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supported_modes_1080p() -> TestResult {
    if !SUPPORTED_MODES.contains(&(1920, 1080)) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_min_width() -> TestResult {
    if MIN_WIDTH != 320 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_min_height() -> TestResult {
    if MIN_HEIGHT != 200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_width() -> TestResult {
    if MAX_WIDTH != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_height() -> TestResult {
    if MAX_HEIGHT != 3072 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_within_bounds() -> TestResult {
    if !(DEFAULT_WIDTH >= MIN_WIDTH) {
        return TestResult::Fail;
    }
    if !(DEFAULT_WIDTH <= MAX_WIDTH) {
        return TestResult::Fail;
    }
    if !(DEFAULT_HEIGHT >= MIN_HEIGHT) {
        return TestResult::Fail;
    }
    if !(DEFAULT_HEIGHT <= MAX_HEIGHT) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vbe_dispi_index_sequential() -> TestResult {
    if VBE_DISPI_INDEX_XRES != VBE_DISPI_INDEX_ID + 1 {
        return TestResult::Fail;
    }
    if VBE_DISPI_INDEX_YRES != VBE_DISPI_INDEX_XRES + 1 {
        return TestResult::Fail;
    }
    if VBE_DISPI_INDEX_BPP != VBE_DISPI_INDEX_YRES + 1 {
        return TestResult::Fail;
    }
    if VBE_DISPI_INDEX_ENABLE != VBE_DISPI_INDEX_BPP + 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vbe_ports_adjacent() -> TestResult {
    if VBE_DATA_PORT != VBE_INDEX_PORT + 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_cmd_bits_distinct() -> TestResult {
    if PCI_CMD_IO_ENABLE & PCI_CMD_MEM_ENABLE != 0 {
        return TestResult::Fail;
    }
    if PCI_CMD_MEM_ENABLE & PCI_CMD_BUS_MASTER != 0 {
        return TestResult::Fail;
    }
    if PCI_CMD_IO_ENABLE & PCI_CMD_BUS_MASTER != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
