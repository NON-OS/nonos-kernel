// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

#[cfg(test)]
mod tests {
    use super::super::constants::*;
    use super::super::surface::*;

    #[test]
    fn test_vbe_constants() {
        assert_eq!(VBE_INDEX_PORT, 0x1CE);
        assert_eq!(VBE_DATA_PORT, 0x1CF);
        assert_eq!(VBE_DISPI_ID_MAGIC, 0xB0C5);
    }

    #[test]
    fn test_vbe_registers() {
        assert_eq!(VBE_DISPI_INDEX_ID, 0x0);
        assert_eq!(VBE_DISPI_INDEX_XRES, 0x1);
        assert_eq!(VBE_DISPI_INDEX_YRES, 0x2);
        assert_eq!(VBE_DISPI_INDEX_BPP, 0x3);
        assert_eq!(VBE_DISPI_INDEX_ENABLE, 0x4);
    }

    #[test]
    fn test_vbe_flags() {
        assert_eq!(VBE_DISPI_ENABLED, 0x01);
        assert_eq!(VBE_DISPI_LFB_ENABLED, 0x40);
        assert_eq!(VBE_DISPI_NOCLEARMEM, 0x80);
    }

    #[test]
    fn test_default_mode() {
        assert_eq!(DEFAULT_WIDTH, 1024);
        assert_eq!(DEFAULT_HEIGHT, 768);
        assert_eq!(DEFAULT_BPP, 32);
    }

    #[test]
    fn test_pci_command_bits() {
        assert_eq!(PCI_CMD_IO_ENABLE, 1);
        assert_eq!(PCI_CMD_MEM_ENABLE, 2);
        assert_eq!(PCI_CMD_BUS_MASTER, 4);
    }

    #[test]
    fn test_pixel_format_bpp() {
        assert_eq!(PixelFormat::X8R8G8B8.bytes_per_pixel(), 4);
        assert_eq!(PixelFormat::A8R8G8B8.bytes_per_pixel(), 4);
        assert_eq!(PixelFormat::R8G8B8.bytes_per_pixel(), 3);
        assert_eq!(PixelFormat::R5G6B5.bytes_per_pixel(), 2);
    }

    #[test]
    fn test_pixel_format_bits() {
        assert_eq!(PixelFormat::X8R8G8B8.bits_per_pixel(), 32);
        assert_eq!(PixelFormat::R5G6B5.bits_per_pixel(), 16);
    }

    #[test]
    fn test_display_mode() {
        let mode = DisplayMode::new(1024, 768, 32);
        assert_eq!(mode.width, 1024);
        assert_eq!(mode.height, 768);
        assert_eq!(mode.bpp, 32);
        assert_eq!(mode.pitch, 1024 * 4);
    }

    #[test]
    fn test_display_mode_framebuffer_size() {
        let mode = DisplayMode::new(1024, 768, 32);
        assert_eq!(mode.framebuffer_size(), 1024 * 768 * 4);
    }

    #[test]
    fn test_display_mode_total_pixels() {
        let mode = DisplayMode::new(1024, 768, 32);
        assert_eq!(mode.total_pixels(), 1024 * 768);
    }

    #[test]
    fn test_pci_ids() {
        assert_eq!(VENDOR_QEMU, 0x1234);
        assert_eq!(DEVICE_STD_VGA, 0x1111);
        assert_eq!(CLASS_DISPLAY, 0x03);
    }

    #[test]
    fn test_supported_modes() {
        assert!(SUPPORTED_MODES.contains(&(1024, 768)));
        assert!(SUPPORTED_MODES.contains(&(1920, 1080)));
        assert!(SUPPORTED_MODES.contains(&(640, 480)));
    }
}
