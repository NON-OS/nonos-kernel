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

pub mod apic_tests;
pub mod clock_tests;
pub mod gdt_tests;
pub mod idt_tests;
pub mod io_tests;
pub mod serial_tests;
pub mod settings_tests;
pub mod timer_tests;

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("sys");

    // apic_tests (34 tests)
    suite.add(TestCase::new("apic::timer_vector_value", apic_tests::test_timer_vector_value));
    suite.add(TestCase::new("apic::irq_timer_value", apic_tests::test_irq_timer_value));
    suite.add(TestCase::new("apic::irq_keyboard_value", apic_tests::test_irq_keyboard_value));
    suite.add(TestCase::new("apic::irq_cascade_value", apic_tests::test_irq_cascade_value));
    suite.add(TestCase::new("apic::irq_com2_value", apic_tests::test_irq_com2_value));
    suite.add(TestCase::new("apic::irq_com1_value", apic_tests::test_irq_com1_value));
    suite.add(TestCase::new("apic::irq_lpt2_value", apic_tests::test_irq_lpt2_value));
    suite.add(TestCase::new("apic::irq_floppy_value", apic_tests::test_irq_floppy_value));
    suite.add(TestCase::new("apic::irq_lpt1_value", apic_tests::test_irq_lpt1_value));
    suite.add(TestCase::new("apic::irq_rtc_value", apic_tests::test_irq_rtc_value));
    suite.add(TestCase::new("apic::irq_free1_value", apic_tests::test_irq_free1_value));
    suite.add(TestCase::new("apic::irq_free2_value", apic_tests::test_irq_free2_value));
    suite.add(TestCase::new("apic::irq_free3_value", apic_tests::test_irq_free3_value));
    suite.add(TestCase::new("apic::irq_mouse_value", apic_tests::test_irq_mouse_value));
    suite.add(TestCase::new("apic::irq_coprocessor_value", apic_tests::test_irq_coprocessor_value));
    suite.add(TestCase::new("apic::irq_primary_ata_value", apic_tests::test_irq_primary_ata_value));
    suite.add(TestCase::new(
        "apic::irq_secondary_ata_value",
        apic_tests::test_irq_secondary_ata_value,
    ));
    suite.add(TestCase::new(
        "apic::vector_timer_equals_timer_vector",
        apic_tests::test_vector_timer_equals_timer_vector,
    ));
    suite.add(TestCase::new("apic::vector_keyboard_value", apic_tests::test_vector_keyboard_value));
    suite.add(TestCase::new("apic::vector_mouse_value", apic_tests::test_vector_mouse_value));
    suite.add(TestCase::new("apic::vector_com1_value", apic_tests::test_vector_com1_value));
    suite.add(TestCase::new("apic::irq_to_vector_timer", apic_tests::test_irq_to_vector_timer));
    suite.add(TestCase::new(
        "apic::irq_to_vector_keyboard",
        apic_tests::test_irq_to_vector_keyboard,
    ));
    suite.add(TestCase::new("apic::irq_to_vector_mouse", apic_tests::test_irq_to_vector_mouse));
    suite.add(TestCase::new("apic::irq_to_vector_com1", apic_tests::test_irq_to_vector_com1));
    suite.add(TestCase::new("apic::irq_to_vector_com2", apic_tests::test_irq_to_vector_com2));
    suite.add(TestCase::new("apic::irq_to_vector_rtc", apic_tests::test_irq_to_vector_rtc));
    suite.add(TestCase::new("apic::irq_to_vector_floppy", apic_tests::test_irq_to_vector_floppy));
    suite.add(TestCase::new(
        "apic::irq_to_vector_primary_ata",
        apic_tests::test_irq_to_vector_primary_ata,
    ));
    suite.add(TestCase::new(
        "apic::irq_to_vector_secondary_ata",
        apic_tests::test_irq_to_vector_secondary_ata,
    ));
    suite.add(TestCase::new(
        "apic::irq_to_vector_base_offset",
        apic_tests::test_irq_to_vector_base_offset,
    ));
    suite.add(TestCase::new(
        "apic::vector_values_above_32",
        apic_tests::test_vector_values_above_32,
    ));
    suite.add(TestCase::new("apic::irq_values_below_16", apic_tests::test_irq_values_below_16));
    suite.add(TestCase::new("apic::all_irqs_unique", apic_tests::test_all_irqs_unique));
    suite.add(TestCase::new(
        "apic::irq_to_vector_is_const",
        apic_tests::test_irq_to_vector_is_const,
    ));

    // clock_tests (24 tests)
    suite.add(TestCase::new(
        "clock::time_struct_hour_range",
        clock_tests::test_time_struct_hour_range,
    ));
    suite.add(TestCase::new(
        "clock::time_struct_minute_range",
        clock_tests::test_time_struct_minute_range,
    ));
    suite.add(TestCase::new(
        "clock::time_struct_second_range",
        clock_tests::test_time_struct_second_range,
    ));
    suite.add(TestCase::new(
        "clock::format_time_buffer_size",
        clock_tests::test_format_time_buffer_size,
    ));
    suite.add(TestCase::new(
        "clock::format_time_colon_position",
        clock_tests::test_format_time_colon_position,
    ));
    suite.add(TestCase::new(
        "clock::format_time_valid_digits",
        clock_tests::test_format_time_valid_digits,
    ));
    suite.add(TestCase::new(
        "clock::format_time_full_buffer_size",
        clock_tests::test_format_time_full_buffer_size,
    ));
    suite.add(TestCase::new(
        "clock::format_time_full_colon_positions",
        clock_tests::test_format_time_full_colon_positions,
    ));
    suite.add(TestCase::new(
        "clock::format_time_full_valid_digits",
        clock_tests::test_format_time_full_valid_digits,
    ));
    suite.add(TestCase::new(
        "clock::format_time_full_hour_range",
        clock_tests::test_format_time_full_hour_range,
    ));
    suite.add(TestCase::new(
        "clock::format_time_full_minute_range",
        clock_tests::test_format_time_full_minute_range,
    ));
    suite.add(TestCase::new(
        "clock::format_time_full_second_range",
        clock_tests::test_format_time_full_second_range,
    ));
    suite.add(TestCase::new(
        "clock::format_date_short_buffer_size",
        clock_tests::test_format_date_short_buffer_size,
    ));
    suite.add(TestCase::new(
        "clock::format_date_short_contains_space",
        clock_tests::test_format_date_short_contains_space,
    ));
    suite.add(TestCase::new(
        "clock::format_date_short_contains_colon",
        clock_tests::test_format_date_short_contains_colon,
    ));
    suite.add(TestCase::new(
        "clock::format_date_short_ends_with_am_or_pm",
        clock_tests::test_format_date_short_ends_with_am_or_pm,
    ));
    suite.add(TestCase::new(
        "clock::format_date_only_buffer_size",
        clock_tests::test_format_date_only_buffer_size,
    ));
    suite.add(TestCase::new(
        "clock::format_date_only_no_time",
        clock_tests::test_format_date_only_no_time,
    ));
    suite.add(TestCase::new(
        "clock::unix_ms_returns_value",
        clock_tests::test_unix_ms_returns_value,
    ));
    suite.add(TestCase::new("clock::unix_ms_monotonic", clock_tests::test_unix_ms_monotonic));
    suite.add(TestCase::new(
        "clock::uptime_seconds_returns_value",
        clock_tests::test_uptime_seconds_returns_value,
    ));
    suite.add(TestCase::new("clock::get_time_consistency", clock_tests::test_get_time_consistency));
    suite.add(TestCase::new(
        "clock::format_time_produces_valid_output",
        clock_tests::test_format_time_produces_valid_output,
    ));
    suite.add(TestCase::new(
        "clock::format_time_full_produces_valid_output",
        clock_tests::test_format_time_full_produces_valid_output,
    ));

    // gdt_tests (3 tests)
    suite.add(TestCase::new("gdt::module_exists", gdt_tests::test_module_exists));
    suite.add(TestCase::new("gdt::basic_constants", gdt_tests::test_basic_constants));
    suite.add(TestCase::new("gdt::basic_operations", gdt_tests::test_basic_operations));

    // idt_tests (4 tests)
    suite.add(TestCase::new("idt::idt_module_exists", idt_tests::test_idt_module_exists));
    suite.add(TestCase::new("idt::idt_entry_count", idt_tests::test_idt_entry_count));
    suite.add(TestCase::new("idt::idt_entry_size", idt_tests::test_idt_entry_size));
    suite.add(TestCase::new("idt::interrupt_vectors", idt_tests::test_interrupt_vectors));

    // io_tests (30 tests)
    suite.add(TestCase::new("io::io_wait_exists", io_tests::test_io_wait_exists));
    suite.add(TestCase::new("io::io_wait_multiple_calls", io_tests::test_io_wait_multiple_calls));
    suite.add(TestCase::new("io::outb_function_signature", io_tests::test_outb_function_signature));
    suite.add(TestCase::new("io::inb_function_signature", io_tests::test_inb_function_signature));
    suite.add(TestCase::new("io::outw_function_signature", io_tests::test_outw_function_signature));
    suite.add(TestCase::new("io::inw_function_signature", io_tests::test_inw_function_signature));
    suite.add(TestCase::new("io::outl_function_signature", io_tests::test_outl_function_signature));
    suite.add(TestCase::new("io::inl_function_signature", io_tests::test_inl_function_signature));
    suite.add(TestCase::new("io::port_types_are_u16", io_tests::test_port_types_are_u16));
    suite.add(TestCase::new("io::byte_value_type", io_tests::test_byte_value_type));
    suite.add(TestCase::new("io::word_value_type", io_tests::test_word_value_type));
    suite.add(TestCase::new("io::dword_value_type", io_tests::test_dword_value_type));
    suite.add(TestCase::new("io::common_port_addresses", io_tests::test_common_port_addresses));
    suite.add(TestCase::new("io::pic_port_addresses", io_tests::test_pic_port_addresses));
    suite.add(TestCase::new("io::keyboard_port_address", io_tests::test_keyboard_port_address));
    suite.add(TestCase::new("io::rtc_port_addresses", io_tests::test_rtc_port_addresses));
    suite.add(TestCase::new("io::cmos_port_addresses", io_tests::test_cmos_port_addresses));
    suite.add(TestCase::new("io::pci_config_ports", io_tests::test_pci_config_ports));
    suite.add(TestCase::new("io::io_wait_port", io_tests::test_io_wait_port));
    suite.add(TestCase::new("io::port_max_value", io_tests::test_port_max_value));
    suite.add(TestCase::new("io::port_min_value", io_tests::test_port_min_value));
    suite.add(TestCase::new("io::byte_boundary_values", io_tests::test_byte_boundary_values));
    suite.add(TestCase::new("io::word_boundary_values", io_tests::test_word_boundary_values));
    suite.add(TestCase::new("io::dword_boundary_values", io_tests::test_dword_boundary_values));
    suite.add(TestCase::new("io::vga_port_addresses", io_tests::test_vga_port_addresses));
    suite.add(TestCase::new("io::ata_primary_ports", io_tests::test_ata_primary_ports));
    suite.add(TestCase::new("io::ata_secondary_ports", io_tests::test_ata_secondary_ports));

    // serial_tests (40 tests)
    suite.add(TestCase::new(
        "serial::serial_port_constant",
        serial_tests::test_serial_port_constant,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_empty_slice",
        serial_tests::test_serial_print_empty_slice,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_single_byte",
        serial_tests::test_serial_print_single_byte,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_multiple_bytes",
        serial_tests::test_serial_print_multiple_bytes,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_special_chars",
        serial_tests::test_serial_print_special_chars,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_str_empty",
        serial_tests::test_serial_print_str_empty,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_str_single",
        serial_tests::test_serial_print_str_single,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_str_multiple",
        serial_tests::test_serial_print_str_multiple,
    ));
    suite.add(TestCase::new(
        "serial::serial_println_empty",
        serial_tests::test_serial_println_empty,
    ));
    suite.add(TestCase::new(
        "serial::serial_println_message",
        serial_tests::test_serial_println_message,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_hex_zero",
        serial_tests::test_serial_print_hex_zero,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_hex_one",
        serial_tests::test_serial_print_hex_one,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_hex_max",
        serial_tests::test_serial_print_hex_max,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_hex_arbitrary",
        serial_tests::test_serial_print_hex_arbitrary,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_hex_powers_of_two",
        serial_tests::test_serial_print_hex_powers_of_two,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_dec_zero",
        serial_tests::test_serial_print_dec_zero,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_dec_one",
        serial_tests::test_serial_print_dec_one,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_dec_max",
        serial_tests::test_serial_print_dec_max,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_dec_arbitrary",
        serial_tests::test_serial_print_dec_arbitrary,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_dec_powers_of_ten",
        serial_tests::test_serial_print_dec_powers_of_ten,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_dec_sequential",
        serial_tests::test_serial_print_dec_sequential,
    ));
    suite.add(TestCase::new(
        "serial::serial_set_debug_enabled_true",
        serial_tests::test_serial_set_debug_enabled_true,
    ));
    suite.add(TestCase::new(
        "serial::serial_set_debug_enabled_false",
        serial_tests::test_serial_set_debug_enabled_false,
    ));
    suite.add(TestCase::new(
        "serial::serial_set_debug_enabled_toggle",
        serial_tests::test_serial_set_debug_enabled_toggle,
    ));
    suite.add(TestCase::new(
        "serial::serial_is_debug_enabled_returns_bool",
        serial_tests::test_serial_is_debug_enabled_returns_bool,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_binary_data",
        serial_tests::test_serial_print_binary_data,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_newline_variations",
        serial_tests::test_serial_print_newline_variations,
    ));
    suite.add(TestCase::new("serial::serial_print_tab", serial_tests::test_serial_print_tab));
    suite.add(TestCase::new(
        "serial::serial_print_all_printable_ascii",
        serial_tests::test_serial_print_all_printable_ascii,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_long_string",
        serial_tests::test_serial_print_long_string,
    ));
    suite.add(TestCase::new(
        "serial::serial_println_adds_newline",
        serial_tests::test_serial_println_adds_newline,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_hex_single_digit",
        serial_tests::test_serial_print_hex_single_digit,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_dec_single_digit",
        serial_tests::test_serial_print_dec_single_digit,
    ));
    suite.add(TestCase::new(
        "serial::serial_combined_output",
        serial_tests::test_serial_combined_output,
    ));
    suite.add(TestCase::new(
        "serial::serial_debug_flag_persistence",
        serial_tests::test_serial_debug_flag_persistence,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_str_utf8",
        serial_tests::test_serial_print_str_utf8,
    ));
    suite.add(TestCase::new(
        "serial::serial_print_u64_alias",
        serial_tests::test_serial_print_u64_alias,
    ));
    suite.add(TestCase::new("serial::serial_port_is_com1", serial_tests::test_serial_port_is_com1));
    suite.add(TestCase::new(
        "serial::serial_related_ports",
        serial_tests::test_serial_related_ports,
    ));

    // settings_tests (82 tests)
    suite.add(TestCase::new(
        "settings::settings_default_brightness",
        settings_tests::test_settings_default_brightness,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_mouse_sensitivity",
        settings_tests::test_settings_default_mouse_sensitivity,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_sound_enabled",
        settings_tests::test_settings_default_sound_enabled,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_anonymous_mode",
        settings_tests::test_settings_default_anonymous_mode,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_nym_enabled",
        settings_tests::test_settings_default_nym_enabled,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_theme",
        settings_tests::test_settings_default_theme,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_keyboard_layout",
        settings_tests::test_settings_default_keyboard_layout,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_auto_wipe",
        settings_tests::test_settings_default_auto_wipe,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_timezone",
        settings_tests::test_settings_default_timezone,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_screen_timeout",
        settings_tests::test_settings_default_screen_timeout,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_language",
        settings_tests::test_settings_default_language,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_developer_mode",
        settings_tests::test_settings_default_developer_mode,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_hardware_crypto",
        settings_tests::test_settings_default_hardware_crypto,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_zk_attestation",
        settings_tests::test_settings_default_zk_attestation,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_system_keys_generated",
        settings_tests::test_settings_default_system_keys_generated,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_notifications_enabled",
        settings_tests::test_settings_default_notifications_enabled,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_high_contrast",
        settings_tests::test_settings_default_high_contrast,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_font_size",
        settings_tests::test_settings_default_font_size,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_auto_lock_timeout",
        settings_tests::test_settings_default_auto_lock_timeout,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_wifi_autoconnect",
        settings_tests::test_settings_default_wifi_autoconnect,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_animations_enabled",
        settings_tests::test_settings_default_animations_enabled,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_cursor_size",
        settings_tests::test_settings_default_cursor_size,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_kernel_aslr",
        settings_tests::test_settings_default_kernel_aslr,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_kernel_stack_guard",
        settings_tests::test_settings_default_kernel_stack_guard,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_kernel_nx_bit",
        settings_tests::test_settings_default_kernel_nx_bit,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_kernel_smep",
        settings_tests::test_settings_default_kernel_smep,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_kernel_smap",
        settings_tests::test_settings_default_kernel_smap,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_kernel_debug",
        settings_tests::test_settings_default_kernel_debug,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_kernel_serial",
        settings_tests::test_settings_default_kernel_serial,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_kernel_watchdog",
        settings_tests::test_settings_default_kernel_watchdog,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_kernel_preempt",
        settings_tests::test_settings_default_kernel_preempt,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_kernel_hugepages",
        settings_tests::test_settings_default_kernel_hugepages,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_kernel_iommu",
        settings_tests::test_settings_default_kernel_iommu,
    ));
    suite.add(TestCase::new(
        "settings::settings_default_kernel_seccomp",
        settings_tests::test_settings_default_kernel_seccomp,
    ));
    suite.add(TestCase::new("settings::settings_is_copy", settings_tests::test_settings_is_copy));
    suite.add(TestCase::new("settings::settings_is_clone", settings_tests::test_settings_is_clone));
    suite.add(TestCase::new(
        "settings::settings_const_default",
        settings_tests::test_settings_const_default,
    ));
    suite.add(TestCase::new("settings::brightness_getter", settings_tests::test_brightness_getter));
    suite.add(TestCase::new(
        "settings::set_brightness_normal",
        settings_tests::test_set_brightness_normal,
    ));
    suite.add(TestCase::new(
        "settings::set_brightness_max",
        settings_tests::test_set_brightness_max,
    ));
    suite.add(TestCase::new(
        "settings::set_brightness_clamp",
        settings_tests::test_set_brightness_clamp,
    ));
    suite.add(TestCase::new(
        "settings::set_brightness_zero",
        settings_tests::test_set_brightness_zero,
    ));
    suite.add(TestCase::new(
        "settings::mouse_sensitivity_getter",
        settings_tests::test_mouse_sensitivity_getter,
    ));
    suite.add(TestCase::new(
        "settings::set_mouse_sensitivity_normal",
        settings_tests::test_set_mouse_sensitivity_normal,
    ));
    suite.add(TestCase::new(
        "settings::set_mouse_sensitivity_clamp_low",
        settings_tests::test_set_mouse_sensitivity_clamp_low,
    ));
    suite.add(TestCase::new(
        "settings::set_mouse_sensitivity_clamp_high",
        settings_tests::test_set_mouse_sensitivity_clamp_high,
    ));
    suite.add(TestCase::new(
        "settings::anonymous_mode_getter",
        settings_tests::test_anonymous_mode_getter,
    ));
    suite.add(TestCase::new(
        "settings::set_anonymous_mode_true",
        settings_tests::test_set_anonymous_mode_true,
    ));
    suite.add(TestCase::new(
        "settings::set_anonymous_mode_false",
        settings_tests::test_set_anonymous_mode_false,
    ));
    suite.add(TestCase::new(
        "settings::nym_enabled_getter",
        settings_tests::test_nym_enabled_getter,
    ));
    suite.add(TestCase::new(
        "settings::set_nym_enabled_true",
        settings_tests::test_set_nym_enabled_true,
    ));
    suite.add(TestCase::new(
        "settings::set_nym_enabled_false",
        settings_tests::test_set_nym_enabled_false,
    ));
    suite.add(TestCase::new("settings::theme_getter", settings_tests::test_theme_getter));
    suite.add(TestCase::new("settings::set_theme", settings_tests::test_set_theme));
    suite.add(TestCase::new("settings::auto_wipe_getter", settings_tests::test_auto_wipe_getter));
    suite.add(TestCase::new(
        "settings::set_auto_wipe_true",
        settings_tests::test_set_auto_wipe_true,
    ));
    suite.add(TestCase::new(
        "settings::set_auto_wipe_false",
        settings_tests::test_set_auto_wipe_false,
    ));
    suite.add(TestCase::new("settings::timezone_getter", settings_tests::test_timezone_getter));
    suite.add(TestCase::new(
        "settings::set_timezone_positive",
        settings_tests::test_set_timezone_positive,
    ));
    suite.add(TestCase::new(
        "settings::set_timezone_negative",
        settings_tests::test_set_timezone_negative,
    ));
    suite.add(TestCase::new(
        "settings::set_timezone_clamp_low",
        settings_tests::test_set_timezone_clamp_low,
    ));
    suite.add(TestCase::new(
        "settings::set_timezone_clamp_high",
        settings_tests::test_set_timezone_clamp_high,
    ));
    suite.add(TestCase::new(
        "settings::get_returns_settings",
        settings_tests::test_get_returns_settings,
    ));
    suite.add(TestCase::new(
        "settings::get_mut_returns_mutable_ref",
        settings_tests::test_get_mut_returns_mutable_ref,
    ));
    suite.add(TestCase::new("settings::mark_modified", settings_tests::test_mark_modified));
    suite.add(TestCase::new(
        "settings::needs_save_returns_bool",
        settings_tests::test_needs_save_returns_bool,
    ));
    suite.add(TestCase::new(
        "settings::serialize_returns_size",
        settings_tests::test_serialize_returns_size,
    ));
    suite.add(TestCase::new(
        "settings::deserialize_roundtrip",
        settings_tests::test_deserialize_roundtrip,
    ));
    suite.add(TestCase::new(
        "settings::settings_filename_constant",
        settings_tests::test_settings_filename_constant,
    ));
    suite.add(TestCase::new("settings::hostname_init", settings_tests::test_hostname_init));
    suite.add(TestCase::new("settings::get_hostname", settings_tests::test_get_hostname));
    suite.add(TestCase::new(
        "settings::set_hostname_valid",
        settings_tests::test_set_hostname_valid,
    ));
    suite.add(TestCase::new(
        "settings::set_hostname_empty_fails",
        settings_tests::test_set_hostname_empty_fails,
    ));
    suite.add(TestCase::new(
        "settings::set_hostname_too_long_fails",
        settings_tests::test_set_hostname_too_long_fails,
    ));
    suite.add(TestCase::new(
        "settings::set_hostname_invalid_chars_fails",
        settings_tests::test_set_hostname_invalid_chars_fails,
    ));
    suite.add(TestCase::new("settings::get_domainname", settings_tests::test_get_domainname));
    suite.add(TestCase::new(
        "settings::set_domainname_valid",
        settings_tests::test_set_domainname_valid,
    ));
    suite.add(TestCase::new(
        "settings::set_domainname_empty",
        settings_tests::test_set_domainname_empty,
    ));
    suite.add(TestCase::new(
        "settings::set_domainname_too_long_fails",
        settings_tests::test_set_domainname_too_long_fails,
    ));
    suite.add(TestCase::new("settings::reset_to_defaults", settings_tests::test_reset_to_defaults));
    suite.add(TestCase::new(
        "settings::screen_timeout_getter",
        settings_tests::test_screen_timeout_getter,
    ));
    suite.add(TestCase::new(
        "settings::set_screen_timeout",
        settings_tests::test_set_screen_timeout,
    ));
    suite.add(TestCase::new(
        "settings::set_screen_timeout_clamp",
        settings_tests::test_set_screen_timeout_clamp,
    ));
    suite.add(TestCase::new(
        "settings::keyboard_layout_getter",
        settings_tests::test_keyboard_layout_getter,
    ));
    suite.add(TestCase::new(
        "settings::set_keyboard_layout",
        settings_tests::test_set_keyboard_layout,
    ));
    suite.add(TestCase::new(
        "settings::set_keyboard_layout_clamp",
        settings_tests::test_set_keyboard_layout_clamp,
    ));
    suite.add(TestCase::new(
        "settings::sound_enabled_getter",
        settings_tests::test_sound_enabled_getter,
    ));
    suite.add(TestCase::new("settings::set_sound_enabled", settings_tests::test_set_sound_enabled));
    suite.add(TestCase::new("settings::language_getter", settings_tests::test_language_getter));
    suite.add(TestCase::new("settings::set_language", settings_tests::test_set_language));
    suite.add(TestCase::new(
        "settings::developer_mode_getter",
        settings_tests::test_developer_mode_getter,
    ));
    suite.add(TestCase::new(
        "settings::set_developer_mode",
        settings_tests::test_set_developer_mode,
    ));
    suite.add(TestCase::new(
        "settings::hardware_crypto_getter",
        settings_tests::test_hardware_crypto_getter,
    ));
    suite.add(TestCase::new(
        "settings::set_hardware_crypto",
        settings_tests::test_set_hardware_crypto,
    ));
    suite.add(TestCase::new(
        "settings::zk_attestation_getter",
        settings_tests::test_zk_attestation_getter,
    ));
    suite.add(TestCase::new(
        "settings::set_zk_attestation",
        settings_tests::test_set_zk_attestation,
    ));
    suite.add(TestCase::new(
        "settings::system_keys_generated_getter",
        settings_tests::test_system_keys_generated_getter,
    ));
    suite.add(TestCase::new(
        "settings::set_system_keys_generated",
        settings_tests::test_set_system_keys_generated,
    ));
    suite.add(TestCase::new(
        "settings::notifications_enabled_getter",
        settings_tests::test_notifications_enabled_getter,
    ));
    suite.add(TestCase::new(
        "settings::set_notifications_enabled",
        settings_tests::test_set_notifications_enabled,
    ));
    suite.add(TestCase::new(
        "settings::animations_enabled_getter",
        settings_tests::test_animations_enabled_getter,
    ));
    suite.add(TestCase::new(
        "settings::set_animations_enabled",
        settings_tests::test_set_animations_enabled,
    ));
    suite.add(TestCase::new(
        "settings::cursor_size_getter",
        settings_tests::test_cursor_size_getter,
    ));
    suite.add(TestCase::new("settings::set_cursor_size", settings_tests::test_set_cursor_size));
    suite.add(TestCase::new(
        "settings::set_cursor_size_clamp",
        settings_tests::test_set_cursor_size_clamp,
    ));
    suite.add(TestCase::new(
        "settings::high_contrast_getter",
        settings_tests::test_high_contrast_getter,
    ));
    suite.add(TestCase::new("settings::set_high_contrast", settings_tests::test_set_high_contrast));
    suite.add(TestCase::new("settings::font_size_getter", settings_tests::test_font_size_getter));
    suite.add(TestCase::new("settings::set_font_size", settings_tests::test_set_font_size));
    suite.add(TestCase::new(
        "settings::set_font_size_clamp",
        settings_tests::test_set_font_size_clamp,
    ));
    suite.add(TestCase::new(
        "settings::auto_lock_timeout_getter",
        settings_tests::test_auto_lock_timeout_getter,
    ));
    suite.add(TestCase::new(
        "settings::set_auto_lock_timeout",
        settings_tests::test_set_auto_lock_timeout,
    ));
    suite.add(TestCase::new(
        "settings::set_auto_lock_timeout_clamp",
        settings_tests::test_set_auto_lock_timeout_clamp,
    ));
    suite.add(TestCase::new(
        "settings::wifi_autoconnect_getter",
        settings_tests::test_wifi_autoconnect_getter,
    ));
    suite.add(TestCase::new(
        "settings::set_wifi_autoconnect",
        settings_tests::test_set_wifi_autoconnect,
    ));

    // timer_tests (43 tests)
    suite.add(TestCase::new("timer::rdtsc_returns_value", timer_tests::test_rdtsc_returns_value));
    suite.add(TestCase::new("timer::rdtsc_increases", timer_tests::test_rdtsc_increases));
    suite.add(TestCase::new("timer::rdtsc_monotonic", timer_tests::test_rdtsc_monotonic));
    suite.add(TestCase::new(
        "timer::tsc_frequency_returns_value",
        timer_tests::test_tsc_frequency_returns_value,
    ));
    suite.add(TestCase::new("timer::ticks_to_ns_zero", timer_tests::test_ticks_to_ns_zero));
    suite.add(TestCase::new("timer::ticks_to_us_zero", timer_tests::test_ticks_to_us_zero));
    suite.add(TestCase::new("timer::ticks_to_ms_zero", timer_tests::test_ticks_to_ms_zero));
    suite.add(TestCase::new("timer::ticks_to_ns_positive", timer_tests::test_ticks_to_ns_positive));
    suite.add(TestCase::new("timer::ticks_to_us_positive", timer_tests::test_ticks_to_us_positive));
    suite.add(TestCase::new("timer::ticks_to_ms_positive", timer_tests::test_ticks_to_ms_positive));
    suite.add(TestCase::new("timer::us_to_ticks_zero", timer_tests::test_us_to_ticks_zero));
    suite.add(TestCase::new("timer::ms_to_ticks_zero", timer_tests::test_ms_to_ticks_zero));
    suite.add(TestCase::new("timer::us_to_ticks_positive", timer_tests::test_us_to_ticks_positive));
    suite.add(TestCase::new("timer::ms_to_ticks_positive", timer_tests::test_ms_to_ticks_positive));
    suite.add(TestCase::new(
        "timer::uptime_ms_returns_value",
        timer_tests::test_uptime_ms_returns_value,
    ));
    suite.add(TestCase::new(
        "timer::uptime_us_returns_value",
        timer_tests::test_uptime_us_returns_value,
    ));
    suite.add(TestCase::new(
        "timer::uptime_seconds_returns_value",
        timer_tests::test_uptime_seconds_returns_value,
    ));
    suite.add(TestCase::new("timer::uptime_ms_monotonic", timer_tests::test_uptime_ms_monotonic));
    suite.add(TestCase::new("timer::uptime_us_monotonic", timer_tests::test_uptime_us_monotonic));
    suite.add(TestCase::new(
        "timer::unix_timestamp_ms_returns_value",
        timer_tests::test_unix_timestamp_ms_returns_value,
    ));
    suite.add(TestCase::new(
        "timer::unix_timestamp_returns_value",
        timer_tests::test_unix_timestamp_returns_value,
    ));
    suite.add(TestCase::new(
        "timer::unix_timestamp_less_than_ms",
        timer_tests::test_unix_timestamp_less_than_ms,
    ));
    suite.add(TestCase::new("timer::stopwatch_start", timer_tests::test_stopwatch_start));
    suite.add(TestCase::new(
        "timer::stopwatch_elapsed_ticks",
        timer_tests::test_stopwatch_elapsed_ticks,
    ));
    suite.add(TestCase::new("timer::stopwatch_elapsed_us", timer_tests::test_stopwatch_elapsed_us));
    suite.add(TestCase::new("timer::stopwatch_elapsed_ms", timer_tests::test_stopwatch_elapsed_ms));
    suite.add(TestCase::new("timer::stopwatch_reset", timer_tests::test_stopwatch_reset));
    suite.add(TestCase::new(
        "timer::stopwatch_elapsed_increases",
        timer_tests::test_stopwatch_elapsed_increases,
    ));
    suite.add(TestCase::new("timer::is_init_returns_bool", timer_tests::test_is_init_returns_bool));
    suite.add(TestCase::new("timer::stats_returns_tuple", timer_tests::test_stats_returns_tuple));
    suite.add(TestCase::new(
        "timer::format_uptime_buffer_size",
        timer_tests::test_format_uptime_buffer_size,
    ));
    suite.add(TestCase::new(
        "timer::format_uptime_colon_positions",
        timer_tests::test_format_uptime_colon_positions,
    ));
    suite.add(TestCase::new(
        "timer::format_uptime_valid_digits",
        timer_tests::test_format_uptime_valid_digits,
    ));
    suite.add(TestCase::new(
        "timer::format_uptime_minute_range",
        timer_tests::test_format_uptime_minute_range,
    ));
    suite.add(TestCase::new(
        "timer::format_uptime_second_range",
        timer_tests::test_format_uptime_second_range,
    ));
    suite.add(TestCase::new("timer::short_delay_exists", timer_tests::test_short_delay_exists));
    suite.add(TestCase::new(
        "timer::short_delay_multiple_calls",
        timer_tests::test_short_delay_multiple_calls,
    ));
    suite.add(TestCase::new(
        "timer::ticks_conversion_roundtrip",
        timer_tests::test_ticks_conversion_roundtrip,
    ));
    suite.add(TestCase::new(
        "timer::ms_to_ticks_roundtrip",
        timer_tests::test_ms_to_ticks_roundtrip,
    ));
    suite.add(TestCase::new("timer::uptime_consistency", timer_tests::test_uptime_consistency));
    suite.add(TestCase::new(
        "timer::stats_freq_matches_tsc_frequency",
        timer_tests::test_stats_freq_matches_tsc_frequency,
    ));
    suite.add(TestCase::new("timer::timer_callback_type", timer_tests::test_timer_callback_type));
    suite.add(TestCase::new("timer::stopwatch_precision", timer_tests::test_stopwatch_precision));

    suite.run()
}
