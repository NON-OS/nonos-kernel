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

pub mod constants;
pub mod error;
pub mod surface;

use crate::test::framework::TestSuite;

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("gpu");

    // constants tests (41 tests)
    suite.add_test("test_vendor_qemu", constants::test_vendor_qemu);
    suite.add_test("test_device_std_vga", constants::test_device_std_vga);
    suite.add_test("test_class_display", constants::test_class_display);
    suite.add_test("test_vbe_index_port", constants::test_vbe_index_port);
    suite.add_test("test_vbe_data_port", constants::test_vbe_data_port);
    suite.add_test("test_vbe_dispi_index_id", constants::test_vbe_dispi_index_id);
    suite.add_test("test_vbe_dispi_index_xres", constants::test_vbe_dispi_index_xres);
    suite.add_test("test_vbe_dispi_index_yres", constants::test_vbe_dispi_index_yres);
    suite.add_test("test_vbe_dispi_index_bpp", constants::test_vbe_dispi_index_bpp);
    suite.add_test("test_vbe_dispi_index_enable", constants::test_vbe_dispi_index_enable);
    suite.add_test("test_vbe_dispi_index_bank", constants::test_vbe_dispi_index_bank);
    suite.add_test("test_vbe_dispi_index_virt_width", constants::test_vbe_dispi_index_virt_width);
    suite.add_test("test_vbe_dispi_index_virt_height", constants::test_vbe_dispi_index_virt_height);
    suite.add_test("test_vbe_dispi_index_x_offset", constants::test_vbe_dispi_index_x_offset);
    suite.add_test("test_vbe_dispi_index_y_offset", constants::test_vbe_dispi_index_y_offset);
    suite.add_test("test_vbe_dispi_enabled", constants::test_vbe_dispi_enabled);
    suite.add_test("test_vbe_dispi_lfb_enabled", constants::test_vbe_dispi_lfb_enabled);
    suite.add_test("test_vbe_dispi_noclearmem", constants::test_vbe_dispi_noclearmem);
    suite.add_test("test_vbe_dispi_id_magic", constants::test_vbe_dispi_id_magic);
    suite.add_test("test_default_width", constants::test_default_width);
    suite.add_test("test_default_height", constants::test_default_height);
    suite.add_test("test_default_bpp", constants::test_default_bpp);
    suite.add_test("test_pci_command_offset", constants::test_pci_command_offset);
    suite.add_test("test_pci_cmd_io_enable", constants::test_pci_cmd_io_enable);
    suite.add_test("test_pci_cmd_mem_enable", constants::test_pci_cmd_mem_enable);
    suite.add_test("test_pci_cmd_bus_master", constants::test_pci_cmd_bus_master);
    suite.add_test("test_supported_modes_not_empty", constants::test_supported_modes_not_empty);
    suite.add_test("test_supported_modes_vga", constants::test_supported_modes_vga);
    suite.add_test("test_supported_modes_svga", constants::test_supported_modes_svga);
    suite.add_test("test_supported_modes_xga", constants::test_supported_modes_xga);
    suite.add_test("test_supported_modes_720p", constants::test_supported_modes_720p);
    suite.add_test("test_supported_modes_sxga", constants::test_supported_modes_sxga);
    suite.add_test("test_supported_modes_1080p", constants::test_supported_modes_1080p);
    suite.add_test("test_min_width", constants::test_min_width);
    suite.add_test("test_min_height", constants::test_min_height);
    suite.add_test("test_max_width", constants::test_max_width);
    suite.add_test("test_max_height", constants::test_max_height);
    suite.add_test("test_default_within_bounds", constants::test_default_within_bounds);
    suite.add_test("test_vbe_dispi_index_sequential", constants::test_vbe_dispi_index_sequential);
    suite.add_test("test_vbe_ports_adjacent", constants::test_vbe_ports_adjacent);
    suite.add_test("test_pci_cmd_bits_distinct", constants::test_pci_cmd_bits_distinct);

    // error tests (37 tests)
    suite.add_test("test_error_device_not_found_str", error::test_error_device_not_found_str);
    suite.add_test(
        "test_error_initialization_failed_str",
        error::test_error_initialization_failed_str,
    );
    suite.add_test("test_error_invalid_bar_str", error::test_error_invalid_bar_str);
    suite.add_test("test_error_unsupported_mode_str", error::test_error_unsupported_mode_str);
    suite.add_test("test_error_invalid_resolution_str", error::test_error_invalid_resolution_str);
    suite.add_test("test_error_invalid_color_depth_str", error::test_error_invalid_color_depth_str);
    suite.add_test(
        "test_error_framebuffer_allocation_failed_str",
        error::test_error_framebuffer_allocation_failed_str,
    );
    suite.add_test("test_error_mode_set_failed_str", error::test_error_mode_set_failed_str);
    suite.add_test("test_error_vsync_timeout_str", error::test_error_vsync_timeout_str);
    suite.add_test("test_error_invalid_coordinates_str", error::test_error_invalid_coordinates_str);
    suite.add_test("test_error_out_of_bounds_str", error::test_error_out_of_bounds_str);
    suite.add_test("test_error_buffer_too_small_str", error::test_error_buffer_too_small_str);
    suite.add_test(
        "test_error_invalid_pixel_format_str",
        error::test_error_invalid_pixel_format_str,
    );
    suite.add_test("test_error_blit_failed_str", error::test_error_blit_failed_str);
    suite.add_test("test_error_cursor_error_str", error::test_error_cursor_error_str);
    suite.add_test(
        "test_error_vsync_timeout_recoverable",
        error::test_error_vsync_timeout_recoverable,
    );
    suite.add_test(
        "test_error_out_of_bounds_recoverable",
        error::test_error_out_of_bounds_recoverable,
    );
    suite.add_test(
        "test_error_invalid_coordinates_recoverable",
        error::test_error_invalid_coordinates_recoverable,
    );
    suite.add_test(
        "test_error_device_not_found_not_recoverable",
        error::test_error_device_not_found_not_recoverable,
    );
    suite.add_test(
        "test_error_initialization_failed_not_recoverable",
        error::test_error_initialization_failed_not_recoverable,
    );
    suite.add_test(
        "test_error_invalid_bar_not_recoverable",
        error::test_error_invalid_bar_not_recoverable,
    );
    suite.add_test(
        "test_error_unsupported_mode_not_recoverable",
        error::test_error_unsupported_mode_not_recoverable,
    );
    suite.add_test(
        "test_error_invalid_resolution_not_recoverable",
        error::test_error_invalid_resolution_not_recoverable,
    );
    suite.add_test(
        "test_error_invalid_color_depth_not_recoverable",
        error::test_error_invalid_color_depth_not_recoverable,
    );
    suite.add_test(
        "test_error_framebuffer_allocation_failed_not_recoverable",
        error::test_error_framebuffer_allocation_failed_not_recoverable,
    );
    suite.add_test(
        "test_error_mode_set_failed_not_recoverable",
        error::test_error_mode_set_failed_not_recoverable,
    );
    suite.add_test(
        "test_error_buffer_too_small_not_recoverable",
        error::test_error_buffer_too_small_not_recoverable,
    );
    suite.add_test(
        "test_error_invalid_pixel_format_not_recoverable",
        error::test_error_invalid_pixel_format_not_recoverable,
    );
    suite.add_test(
        "test_error_blit_failed_not_recoverable",
        error::test_error_blit_failed_not_recoverable,
    );
    suite.add_test(
        "test_error_cursor_error_not_recoverable",
        error::test_error_cursor_error_not_recoverable,
    );
    suite.add_test("test_error_equality", error::test_error_equality);
    suite.add_test("test_error_copy", error::test_error_copy);
    suite.add_test("test_error_clone", error::test_error_clone);
    suite.add_test("test_error_debug", error::test_error_debug);
    suite.add_test("test_error_display", error::test_error_display);
    suite.add_test("test_all_errors_have_message", error::test_all_errors_have_message);

    // surface tests (32 tests)
    suite.add_test("test_pixel_format_x8r8g8b8_bytes", surface::test_pixel_format_x8r8g8b8_bytes);
    suite.add_test("test_pixel_format_a8r8g8b8_bytes", surface::test_pixel_format_a8r8g8b8_bytes);
    suite.add_test("test_pixel_format_r8g8b8_bytes", surface::test_pixel_format_r8g8b8_bytes);
    suite.add_test("test_pixel_format_r5g6b5_bytes", surface::test_pixel_format_r5g6b5_bytes);
    suite.add_test("test_pixel_format_x8r8g8b8_bits", surface::test_pixel_format_x8r8g8b8_bits);
    suite.add_test("test_pixel_format_a8r8g8b8_bits", surface::test_pixel_format_a8r8g8b8_bits);
    suite.add_test("test_pixel_format_r8g8b8_bits", surface::test_pixel_format_r8g8b8_bits);
    suite.add_test("test_pixel_format_r5g6b5_bits", surface::test_pixel_format_r5g6b5_bits);
    suite.add_test("test_pixel_format_equality", surface::test_pixel_format_equality);
    suite.add_test("test_pixel_format_copy", surface::test_pixel_format_copy);
    suite.add_test("test_pixel_format_clone", surface::test_pixel_format_clone);
    suite.add_test("test_display_mode_new", surface::test_display_mode_new);
    suite.add_test("test_display_mode_pitch_32bpp", surface::test_display_mode_pitch_32bpp);
    suite.add_test("test_display_mode_pitch_24bpp", surface::test_display_mode_pitch_24bpp);
    suite.add_test("test_display_mode_pitch_16bpp", surface::test_display_mode_pitch_16bpp);
    suite.add_test(
        "test_display_mode_framebuffer_size_32bpp",
        surface::test_display_mode_framebuffer_size_32bpp,
    );
    suite.add_test(
        "test_display_mode_framebuffer_size_16bpp",
        surface::test_display_mode_framebuffer_size_16bpp,
    );
    suite.add_test("test_display_mode_total_pixels", surface::test_display_mode_total_pixels);
    suite.add_test(
        "test_display_mode_total_pixels_1080p",
        surface::test_display_mode_total_pixels_1080p,
    );
    suite.add_test("test_display_mode_vga", surface::test_display_mode_vga);
    suite.add_test("test_display_mode_svga", surface::test_display_mode_svga);
    suite.add_test("test_display_mode_xga", surface::test_display_mode_xga);
    suite.add_test("test_display_mode_full_hd", surface::test_display_mode_full_hd);
    suite.add_test("test_display_mode_copy", surface::test_display_mode_copy);
    suite.add_test("test_display_mode_clone", surface::test_display_mode_clone);
    suite.add_test("test_display_mode_debug", surface::test_display_mode_debug);
    suite.add_test("test_pixel_format_debug", surface::test_pixel_format_debug);
    suite.add_test(
        "test_display_mode_framebuffer_size_matches_pitch_times_height",
        surface::test_display_mode_framebuffer_size_matches_pitch_times_height,
    );
    suite.add_test(
        "test_pixel_format_bits_matches_bytes_times_8",
        surface::test_pixel_format_bits_matches_bytes_times_8,
    );

    suite.run()
}
