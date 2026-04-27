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
pub mod dma;
pub mod error;
pub mod stats;
pub mod types;

use crate::test::framework::TestSuite;

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("ahci");

    // constants tests (17 tests)
    suite.add_test("test_hba_register_offsets", constants::test_hba_register_offsets);
    suite.add_test("test_port_register_offsets", constants::test_port_register_offsets);
    suite.add_test("test_cmd_bits", constants::test_cmd_bits);
    suite.add_test("test_cmd_bits_unique", constants::test_cmd_bits_unique);
    suite.add_test("test_is_tfes_bit", constants::test_is_tfes_bit);
    suite.add_test("test_fis_type_values", constants::test_fis_type_values);
    suite.add_test("test_ata_identify_command", constants::test_ata_identify_command);
    suite.add_test("test_ata_read_write_commands", constants::test_ata_read_write_commands);
    suite.add_test("test_ata_dsm_command", constants::test_ata_dsm_command);
    suite.add_test("test_ata_security_commands", constants::test_ata_security_commands);
    suite.add_test("test_max_device_sectors", constants::test_max_device_sectors);
    suite.add_test("test_command_timeouts", constants::test_command_timeouts);
    suite.add_test("test_trim_rate_limit", constants::test_trim_rate_limit);
    suite.add_test("test_port_reset_timeout", constants::test_port_reset_timeout);
    suite.add_test("test_command_slot_constants", constants::test_command_slot_constants);
    suite.add_test("test_port_register_spacing", constants::test_port_register_spacing);
    suite.add_test("test_hba_register_spacing", constants::test_hba_register_spacing);

    // dma tests (3 tests)
    suite.add_test("test_module_exists", dma::test_module_exists);
    suite.add_test("test_basic_constants", dma::test_basic_constants);
    suite.add_test("test_basic_operations", dma::test_basic_operations);

    // error tests (40 tests)
    suite.add_test("test_error_as_str_bar5", error::test_error_as_str_bar5);
    suite.add_test("test_error_as_str_hba_reset", error::test_error_as_str_hba_reset);
    suite.add_test("test_error_as_str_bios_handoff", error::test_error_as_str_bios_handoff);
    suite.add_test("test_error_as_str_port_cmd_list", error::test_error_as_str_port_cmd_list);
    suite.add_test("test_error_as_str_port_fis", error::test_error_as_str_port_fis);
    suite.add_test("test_error_as_str_zero_sector", error::test_error_as_str_zero_sector);
    suite.add_test("test_error_as_str_port_not_init", error::test_error_as_str_port_not_init);
    suite.add_test("test_error_as_str_lba_range", error::test_error_as_str_lba_range);
    suite.add_test("test_error_as_str_lba_overflow", error::test_error_as_str_lba_overflow);
    suite.add_test("test_error_as_str_invalid_buffer", error::test_error_as_str_invalid_buffer);
    suite.add_test("test_error_as_str_buffer_overflow", error::test_error_as_str_buffer_overflow);
    suite.add_test("test_error_as_str_buffer_critical", error::test_error_as_str_buffer_critical);
    suite.add_test("test_error_as_str_buffer_alignment", error::test_error_as_str_buffer_alignment);
    suite.add_test("test_error_as_str_no_slots", error::test_error_as_str_no_slots);
    suite.add_test("test_error_as_str_command_failed", error::test_error_as_str_command_failed);
    suite.add_test("test_error_as_str_command_timeout", error::test_error_as_str_command_timeout);
    suite.add_test(
        "test_error_as_str_trim_not_supported",
        error::test_error_as_str_trim_not_supported,
    );
    suite.add_test("test_error_as_str_trim_rate_limit", error::test_error_as_str_trim_rate_limit);
    suite.add_test("test_error_as_str_secure_erase", error::test_error_as_str_secure_erase);
    suite.add_test("test_error_as_str_cipher", error::test_error_as_str_cipher);
    suite.add_test("test_error_as_str_port_dma", error::test_error_as_str_port_dma);
    suite.add_test("test_error_as_str_dma_alloc", error::test_error_as_str_dma_alloc);
    suite.add_test("test_error_as_str_port_reset", error::test_error_as_str_port_reset);
    suite.add_test("test_error_as_str_no_controller", error::test_error_as_str_no_controller);
    suite.add_test("test_error_equality", error::test_error_equality);
    suite.add_test("test_error_copy", error::test_error_copy);
    suite.add_test("test_error_clone", error::test_error_clone);
    suite.add_test("test_error_from_str_port_not_init", error::test_error_from_str_port_not_init);
    suite.add_test("test_error_from_str_trim", error::test_error_from_str_trim);
    suite.add_test("test_error_from_str_trim_rate", error::test_error_from_str_trim_rate);
    suite.add_test("test_error_from_str_secure_erase", error::test_error_from_str_secure_erase);
    suite.add_test("test_error_from_str_unknown", error::test_error_from_str_unknown);
    suite.add_test("test_error_from_str_bar5", error::test_error_from_str_bar5);
    suite.add_test("test_error_from_str_zero_sectors", error::test_error_from_str_zero_sectors);
    suite.add_test("test_error_from_str_cmd_list_stop", error::test_error_from_str_cmd_list_stop);
    suite.add_test("test_error_from_str_fis_stop", error::test_error_from_str_fis_stop);
    suite.add_test("test_error_debug", error::test_error_debug);
    suite.add_test("test_error_display", error::test_error_display);
    suite.add_test(
        "test_all_error_variants_have_message",
        error::test_all_error_variants_have_message,
    );
    suite.add_test("test_error_variant_count", error::test_error_variant_count);

    // stats tests (14 tests)
    suite.add_test("test_stats_default_read_ops", stats::test_stats_default_read_ops);
    suite.add_test("test_stats_default_write_ops", stats::test_stats_default_write_ops);
    suite.add_test("test_stats_default_trim_ops", stats::test_stats_default_trim_ops);
    suite.add_test("test_stats_default_errors", stats::test_stats_default_errors);
    suite.add_test("test_stats_default_bytes_read", stats::test_stats_default_bytes_read);
    suite.add_test("test_stats_default_bytes_written", stats::test_stats_default_bytes_written);
    suite.add_test("test_stats_default_devices_count", stats::test_stats_default_devices_count);
    suite.add_test("test_stats_default_port_resets", stats::test_stats_default_port_resets);
    suite.add_test(
        "test_stats_default_validation_failures",
        stats::test_stats_default_validation_failures,
    );
    suite.add_test("test_stats_copy", stats::test_stats_copy);
    suite.add_test("test_stats_clone", stats::test_stats_clone);
    suite.add_test("test_stats_debug", stats::test_stats_debug);
    suite.add_test("test_stats_field_independence", stats::test_stats_field_independence);
    suite.add_test("test_stats_large_values", stats::test_stats_large_values);

    // types tests (30 tests)
    suite.add_test("test_device_type_sata_str", types::test_device_type_sata_str);
    suite.add_test("test_device_type_satapi_str", types::test_device_type_satapi_str);
    suite.add_test("test_device_type_semb_str", types::test_device_type_semb_str);
    suite.add_test("test_device_type_pm_str", types::test_device_type_pm_str);
    suite.add_test(
        "test_device_type_from_signature_sata",
        types::test_device_type_from_signature_sata,
    );
    suite.add_test(
        "test_device_type_from_signature_satapi",
        types::test_device_type_from_signature_satapi,
    );
    suite.add_test(
        "test_device_type_from_signature_semb",
        types::test_device_type_from_signature_semb,
    );
    suite.add_test("test_device_type_from_signature_pm", types::test_device_type_from_signature_pm);
    suite.add_test(
        "test_device_type_from_signature_invalid_zero",
        types::test_device_type_from_signature_invalid_zero,
    );
    suite.add_test(
        "test_device_type_from_signature_invalid_random",
        types::test_device_type_from_signature_invalid_random,
    );
    suite.add_test(
        "test_device_type_from_signature_invalid_partial",
        types::test_device_type_from_signature_invalid_partial,
    );
    suite.add_test("test_device_type_equality", types::test_device_type_equality);
    suite.add_test("test_device_type_copy", types::test_device_type_copy);
    suite.add_test("test_device_type_clone", types::test_device_type_clone);
    suite.add_test("test_device_type_debug", types::test_device_type_debug);
    suite.add_test("test_command_header_size", types::test_command_header_size);
    suite.add_test("test_prdt_entry_size", types::test_prdt_entry_size);
    suite.add_test("test_command_table_alignment", types::test_command_table_alignment);
    suite.add_test("test_command_header_layout", types::test_command_header_layout);
    suite.add_test(
        "test_command_header_reserved_zeroed",
        types::test_command_header_reserved_zeroed,
    );
    suite.add_test("test_prdt_layout", types::test_prdt_layout);
    suite.add_test("test_hdr_flags_read_cfl_5", types::test_hdr_flags_read_cfl_5);
    suite.add_test("test_hdr_flags_write_cfl_5", types::test_hdr_flags_write_cfl_5);
    suite.add_test("test_hdr_flags_cfl_range", types::test_hdr_flags_cfl_range);
    suite.add_test("test_hdr_flags_cfl_overflow", types::test_hdr_flags_cfl_overflow);
    suite.add_test("test_hdr_flags_cfl_max", types::test_hdr_flags_cfl_max);
    suite.add_test("test_hdr_flags_cfl_zero", types::test_hdr_flags_cfl_zero);
    suite.add_test("test_hdr_flags_write_bit_position", types::test_hdr_flags_write_bit_position);
    suite.add_test("test_ahci_hba_size", types::test_ahci_hba_size);
    suite.add_test("test_command_table_cfis_size", types::test_command_table_cfis_size);
    suite.add_test("test_command_table_acmd_size", types::test_command_table_acmd_size);
    suite.add_test("test_command_table_reserved_size", types::test_command_table_reserved_size);

    suite.run()
}
