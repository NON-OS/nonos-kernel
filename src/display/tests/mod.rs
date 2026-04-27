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

use crate::test::framework::{TestCase, TestSuite};

pub mod error;
pub mod font;
pub mod framebuffer;
pub mod text;

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("display");

    // Error tests (12 tests)
    suite.add(TestCase::new(
        "display_error_not_initialized_display",
        error::test_display_error_not_initialized_display,
    ));
    suite.add(TestCase::new(
        "display_error_invalid_address_display",
        error::test_display_error_invalid_address_display,
    ));
    suite.add(TestCase::new(
        "display_error_out_of_bounds_display",
        error::test_display_error_out_of_bounds_display,
    ));
    suite.add(TestCase::new(
        "display_error_invalid_format_display",
        error::test_display_error_invalid_format_display,
    ));
    suite.add(TestCase::new(
        "display_error_no_framebuffer_display",
        error::test_display_error_no_framebuffer_display,
    ));
    suite.add(TestCase::new("display_error_equality", error::test_display_error_equality));
    suite.add(TestCase::new("display_error_inequality", error::test_display_error_inequality));
    suite.add(TestCase::new("display_error_debug", error::test_display_error_debug));
    suite.add(TestCase::new("display_error_clone", error::test_display_error_clone));
    suite.add(TestCase::new("display_error_copy", error::test_display_error_copy));
    suite
        .add(TestCase::new("all_error_variants_distinct", error::test_all_error_variants_distinct));
    suite.add(TestCase::new(
        "display_error_debug_all_variants",
        error::test_display_error_debug_all_variants,
    ));

    // Font tests (52 tests)
    suite.add(TestCase::new("get_glyph_space", font::test_get_glyph_space));
    suite.add(TestCase::new("get_glyph_exclamation", font::test_get_glyph_exclamation));
    suite.add(TestCase::new("get_glyph_digit_zero", font::test_get_glyph_digit_zero));
    suite.add(TestCase::new("get_glyph_digit_nine", font::test_get_glyph_digit_nine));
    suite.add(TestCase::new("get_glyph_uppercase_a", font::test_get_glyph_uppercase_a));
    suite.add(TestCase::new("get_glyph_uppercase_z", font::test_get_glyph_uppercase_z));
    suite.add(TestCase::new("get_glyph_lowercase_a", font::test_get_glyph_lowercase_a));
    suite.add(TestCase::new("get_glyph_lowercase_z", font::test_get_glyph_lowercase_z));
    suite.add(TestCase::new("get_glyph_at_symbol", font::test_get_glyph_at_symbol));
    suite.add(TestCase::new("get_glyph_hash", font::test_get_glyph_hash));
    suite.add(TestCase::new("get_glyph_dollar", font::test_get_glyph_dollar));
    suite.add(TestCase::new("get_glyph_percent", font::test_get_glyph_percent));
    suite.add(TestCase::new("get_glyph_asterisk", font::test_get_glyph_asterisk));
    suite.add(TestCase::new("get_glyph_plus", font::test_get_glyph_plus));
    suite.add(TestCase::new("get_glyph_minus", font::test_get_glyph_minus));
    suite.add(TestCase::new("get_glyph_period", font::test_get_glyph_period));
    suite.add(TestCase::new("get_glyph_slash", font::test_get_glyph_slash));
    suite.add(TestCase::new("get_glyph_colon", font::test_get_glyph_colon));
    suite.add(TestCase::new("get_glyph_semicolon", font::test_get_glyph_semicolon));
    suite.add(TestCase::new("get_glyph_less_than", font::test_get_glyph_less_than));
    suite.add(TestCase::new("get_glyph_equals", font::test_get_glyph_equals));
    suite.add(TestCase::new("get_glyph_greater_than", font::test_get_glyph_greater_than));
    suite.add(TestCase::new("get_glyph_question", font::test_get_glyph_question));
    suite.add(TestCase::new("get_glyph_open_bracket", font::test_get_glyph_open_bracket));
    suite.add(TestCase::new("get_glyph_close_bracket", font::test_get_glyph_close_bracket));
    suite.add(TestCase::new("get_glyph_backslash", font::test_get_glyph_backslash));
    suite.add(TestCase::new("get_glyph_caret", font::test_get_glyph_caret));
    suite.add(TestCase::new("get_glyph_underscore", font::test_get_glyph_underscore));
    suite.add(TestCase::new("get_glyph_backtick", font::test_get_glyph_backtick));
    suite.add(TestCase::new("get_glyph_open_brace", font::test_get_glyph_open_brace));
    suite.add(TestCase::new("get_glyph_close_brace", font::test_get_glyph_close_brace));
    suite.add(TestCase::new("get_glyph_pipe", font::test_get_glyph_pipe));
    suite.add(TestCase::new("get_glyph_tilde", font::test_get_glyph_tilde));
    suite.add(TestCase::new(
        "get_glyph_unknown_returns_empty",
        font::test_get_glyph_unknown_returns_empty,
    ));
    suite.add(TestCase::new(
        "get_glyph_high_ascii_returns_empty",
        font::test_get_glyph_high_ascii_returns_empty,
    ));
    suite.add(TestCase::new(
        "get_glyph_control_char_returns_empty",
        font::test_get_glyph_control_char_returns_empty,
    ));
    suite.add(TestCase::new(
        "get_glyph_all_digits_different",
        font::test_get_glyph_all_digits_different,
    ));
    suite.add(TestCase::new(
        "get_glyph_all_uppercase_different",
        font::test_get_glyph_all_uppercase_different,
    ));
    suite.add(TestCase::new(
        "get_glyph_all_lowercase_different",
        font::test_get_glyph_all_lowercase_different,
    ));
    suite.add(TestCase::new(
        "get_glyph_uppercase_lowercase_different",
        font::test_get_glyph_uppercase_lowercase_different,
    ));
    suite.add(TestCase::new("glyph_size_is_16_bytes", font::test_glyph_size_is_16_bytes));
    suite.add(TestCase::new(
        "get_glyph_printable_range_0x20_to_0x2f",
        font::test_get_glyph_printable_range_0x20_to_0x2f,
    ));
    suite.add(TestCase::new(
        "get_glyph_printable_range_0x30_to_0x3f",
        font::test_get_glyph_printable_range_0x30_to_0x3f,
    ));
    suite.add(TestCase::new(
        "get_glyph_printable_range_0x40_to_0x4f",
        font::test_get_glyph_printable_range_0x40_to_0x4f,
    ));
    suite.add(TestCase::new(
        "get_glyph_printable_range_0x50_to_0x5f",
        font::test_get_glyph_printable_range_0x50_to_0x5f,
    ));
    suite.add(TestCase::new(
        "get_glyph_printable_range_0x60_to_0x6f",
        font::test_get_glyph_printable_range_0x60_to_0x6f,
    ));
    suite.add(TestCase::new(
        "get_glyph_printable_range_0x70_to_0x7e",
        font::test_get_glyph_printable_range_0x70_to_0x7e,
    ));
    suite.add(TestCase::new("get_glyph_open_paren", font::test_get_glyph_open_paren));
    suite.add(TestCase::new("get_glyph_close_paren", font::test_get_glyph_close_paren));
    suite.add(TestCase::new("get_glyph_comma", font::test_get_glyph_comma));
    suite.add(TestCase::new("get_glyph_double_quote", font::test_get_glyph_double_quote));
    suite.add(TestCase::new("get_glyph_single_quote", font::test_get_glyph_single_quote));
    suite.add(TestCase::new("get_glyph_ampersand", font::test_get_glyph_ampersand));
    suite.add(TestCase::new("glyph_consistent_retrieval", font::test_glyph_consistent_retrieval));
    suite.add(TestCase::new(
        "all_printable_ascii_have_glyphs",
        font::test_all_printable_ascii_have_glyphs,
    ));

    // Framebuffer tests (34 tests)
    suite.add(TestCase::new(
        "framebuffer_info_creation",
        framebuffer::test_framebuffer_info_creation,
    ));
    suite.add(TestCase::new("framebuffer_info_clone", framebuffer::test_framebuffer_info_clone));
    suite.add(TestCase::new("framebuffer_info_copy", framebuffer::test_framebuffer_info_copy));
    suite.add(TestCase::new("framebuffer_info_debug", framebuffer::test_framebuffer_info_debug));
    suite.add(TestCase::new(
        "framebuffer_info_standard_resolutions",
        framebuffer::test_framebuffer_info_standard_resolutions,
    ));
    suite.add(TestCase::new(
        "framebuffer_info_stride_calculation",
        framebuffer::test_framebuffer_info_stride_calculation,
    ));
    suite.add(TestCase::new(
        "framebuffer_info_stride_with_padding",
        framebuffer::test_framebuffer_info_stride_with_padding,
    ));
    suite.add(TestCase::new(
        "framebuffer_info_vga_resolution",
        framebuffer::test_framebuffer_info_vga_resolution,
    ));
    suite.add(TestCase::new(
        "framebuffer_info_svga_resolution",
        framebuffer::test_framebuffer_info_svga_resolution,
    ));
    suite.add(TestCase::new(
        "framebuffer_info_xga_resolution",
        framebuffer::test_framebuffer_info_xga_resolution,
    ));
    suite.add(TestCase::new(
        "framebuffer_info_sxga_resolution",
        framebuffer::test_framebuffer_info_sxga_resolution,
    ));
    suite.add(TestCase::new("framebuffer_info_bpp_24", framebuffer::test_framebuffer_info_bpp_24));
    suite.add(TestCase::new("framebuffer_info_bpp_16", framebuffer::test_framebuffer_info_bpp_16));
    suite.add(TestCase::new("framebuffer_info_bpp_8", framebuffer::test_framebuffer_info_bpp_8));
    suite.add(TestCase::new(
        "framebuffer_info_large_address",
        framebuffer::test_framebuffer_info_large_address,
    ));
    suite.add(TestCase::new(
        "framebuffer_info_buffer_size",
        framebuffer::test_framebuffer_info_buffer_size,
    ));
    suite.add(TestCase::new(
        "framebuffer_info_pixel_offset",
        framebuffer::test_framebuffer_info_pixel_offset,
    ));
    suite.add(TestCase::new(
        "framebuffer_info_row_offset",
        framebuffer::test_framebuffer_info_row_offset,
    ));
    suite.add(TestCase::new(
        "register_framebuffer_invalid_address_zero",
        framebuffer::test_register_framebuffer_invalid_address_zero,
    ));
    suite.add(TestCase::new(
        "register_framebuffer_invalid_width_zero",
        framebuffer::test_register_framebuffer_invalid_width_zero,
    ));
    suite.add(TestCase::new(
        "register_framebuffer_invalid_height_zero",
        framebuffer::test_register_framebuffer_invalid_height_zero,
    ));
    suite.add(TestCase::new(
        "register_framebuffer_invalid_both_dimensions_zero",
        framebuffer::test_register_framebuffer_invalid_both_dimensions_zero,
    ));
    suite.add(TestCase::new(
        "framebuffer_info_widescreen_16_9",
        framebuffer::test_framebuffer_info_widescreen_16_9,
    ));
    suite.add(TestCase::new(
        "framebuffer_info_widescreen_16_10",
        framebuffer::test_framebuffer_info_widescreen_16_10,
    ));
    suite.add(TestCase::new(
        "framebuffer_info_standard_4_3",
        framebuffer::test_framebuffer_info_standard_4_3,
    ));
    suite.add(TestCase::new(
        "framebuffer_info_retina_2x",
        framebuffer::test_framebuffer_info_retina_2x,
    ));
    suite.add(TestCase::new(
        "framebuffer_info_5k_resolution",
        framebuffer::test_framebuffer_info_5k_resolution,
    ));
    suite.add(TestCase::new(
        "framebuffer_info_bytes_per_pixel_32",
        framebuffer::test_framebuffer_info_bytes_per_pixel_32,
    ));
    suite.add(TestCase::new(
        "framebuffer_info_ultrawide_21_9",
        framebuffer::test_framebuffer_info_ultrawide_21_9,
    ));
    suite.add(TestCase::new(
        "framebuffer_info_square_display",
        framebuffer::test_framebuffer_info_square_display,
    ));
    suite.add(TestCase::new(
        "framebuffer_info_minimum_dimensions",
        framebuffer::test_framebuffer_info_minimum_dimensions,
    ));
    suite.add(TestCase::new(
        "framebuffer_info_max_u32_dimensions",
        framebuffer::test_framebuffer_info_max_u32_dimensions,
    ));

    // Text tests (3 tests)
    suite.add(TestCase::new("module_exists", text::test_module_exists));
    suite.add(TestCase::new("basic_constants", text::test_basic_constants));
    suite.add(TestCase::new("basic_operations", text::test_basic_operations));

    suite.run()
}
