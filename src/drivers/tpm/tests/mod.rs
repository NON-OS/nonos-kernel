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
pub mod measurement;
pub mod status;

use crate::test::framework::TestSuite;

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("tpm");

    // constants tests (79 tests)
    suite.add_test("test_tpm_mmio_base", constants::test_tpm_mmio_base);
    suite.add_test("test_tpm_mmio_size", constants::test_tpm_mmio_size);
    suite.add_test("test_tpm_locality_0", constants::test_tpm_locality_0);
    suite.add_test("test_tpm_locality_1", constants::test_tpm_locality_1);
    suite.add_test("test_tpm_locality_2", constants::test_tpm_locality_2);
    suite.add_test("test_tpm_locality_3", constants::test_tpm_locality_3);
    suite.add_test("test_tpm_locality_4", constants::test_tpm_locality_4);
    suite.add_test("test_regs_tpm_access", constants::test_regs_tpm_access);
    suite.add_test("test_regs_tpm_int_enable", constants::test_regs_tpm_int_enable);
    suite.add_test("test_regs_tpm_int_vector", constants::test_regs_tpm_int_vector);
    suite.add_test("test_regs_tpm_int_status", constants::test_regs_tpm_int_status);
    suite.add_test("test_regs_tpm_intf_caps", constants::test_regs_tpm_intf_caps);
    suite.add_test("test_regs_tpm_sts", constants::test_regs_tpm_sts);
    suite.add_test("test_regs_tpm_data_fifo", constants::test_regs_tpm_data_fifo);
    suite.add_test("test_regs_tpm_interface_id", constants::test_regs_tpm_interface_id);
    suite.add_test("test_regs_tpm_xdata_fifo", constants::test_regs_tpm_xdata_fifo);
    suite.add_test("test_regs_tpm_did_vid", constants::test_regs_tpm_did_vid);
    suite.add_test("test_regs_tpm_rid", constants::test_regs_tpm_rid);
    suite.add_test("test_access_valid", constants::test_access_valid);
    suite.add_test("test_access_active_locality", constants::test_access_active_locality);
    suite.add_test("test_access_been_seized", constants::test_access_been_seized);
    suite.add_test("test_access_seize", constants::test_access_seize);
    suite.add_test("test_access_pending_request", constants::test_access_pending_request);
    suite.add_test("test_access_request_use", constants::test_access_request_use);
    suite.add_test("test_access_establishment", constants::test_access_establishment);
    suite.add_test("test_sts_family_tpm2", constants::test_sts_family_tpm2);
    suite.add_test("test_sts_reset_establishment", constants::test_sts_reset_establishment);
    suite.add_test("test_sts_command_cancel", constants::test_sts_command_cancel);
    suite.add_test("test_sts_valid", constants::test_sts_valid);
    suite.add_test("test_sts_command_ready", constants::test_sts_command_ready);
    suite.add_test("test_sts_go", constants::test_sts_go);
    suite.add_test("test_sts_data_avail", constants::test_sts_data_avail);
    suite.add_test("test_sts_data_expect", constants::test_sts_data_expect);
    suite.add_test("test_sts_selftest_done", constants::test_sts_selftest_done);
    suite.add_test("test_sts_response_retry", constants::test_sts_response_retry);
    suite.add_test("test_commands_startup", constants::test_commands_startup);
    suite.add_test("test_commands_shutdown", constants::test_commands_shutdown);
    suite.add_test("test_commands_self_test", constants::test_commands_self_test);
    suite.add_test("test_commands_pcr_extend", constants::test_commands_pcr_extend);
    suite.add_test("test_commands_pcr_read", constants::test_commands_pcr_read);
    suite.add_test("test_commands_pcr_reset", constants::test_commands_pcr_reset);
    suite.add_test("test_commands_get_random", constants::test_commands_get_random);
    suite.add_test("test_commands_get_capability", constants::test_commands_get_capability);
    suite.add_test("test_commands_hash", constants::test_commands_hash);
    suite.add_test("test_commands_create_primary", constants::test_commands_create_primary);
    suite.add_test("test_commands_create", constants::test_commands_create);
    suite.add_test("test_commands_load", constants::test_commands_load);
    suite.add_test("test_commands_unseal", constants::test_commands_unseal);
    suite.add_test("test_commands_quote", constants::test_commands_quote);
    suite.add_test("test_commands_clear", constants::test_commands_clear);
    suite.add_test("test_alg_sha1", constants::test_alg_sha1);
    suite.add_test("test_alg_sha256", constants::test_alg_sha256);
    suite.add_test("test_alg_sha384", constants::test_alg_sha384);
    suite.add_test("test_alg_sha512", constants::test_alg_sha512);
    suite.add_test("test_alg_sha3_256", constants::test_alg_sha3_256);
    suite.add_test("test_alg_sha3_384", constants::test_alg_sha3_384);
    suite.add_test("test_alg_sha3_512", constants::test_alg_sha3_512);
    suite.add_test("test_alg_null", constants::test_alg_null);
    suite.add_test("test_alg_rsa", constants::test_alg_rsa);
    suite.add_test("test_alg_ecc", constants::test_alg_ecc);
    suite.add_test("test_startup_clear", constants::test_startup_clear);
    suite.add_test("test_startup_state", constants::test_startup_state);
    suite.add_test("test_pcr_bios_start", constants::test_pcr_bios_start);
    suite.add_test("test_pcr_bios_end", constants::test_pcr_bios_end);
    suite.add_test("test_pcr_os_start", constants::test_pcr_os_start);
    suite.add_test("test_pcr_os_end", constants::test_pcr_os_end);
    suite.add_test("test_pcr_debug", constants::test_pcr_debug);
    suite.add_test("test_pcr_locality_3", constants::test_pcr_locality_3);
    suite.add_test("test_pcr_locality_4", constants::test_pcr_locality_4);
    suite.add_test("test_pcr_application", constants::test_pcr_application);
    suite.add_test("test_pcr_nonos_bootloader", constants::test_pcr_nonos_bootloader);
    suite.add_test("test_pcr_nonos_bootloader_config", constants::test_pcr_nonos_bootloader_config);
    suite.add_test("test_pcr_nonos_kernel", constants::test_pcr_nonos_kernel);
    suite.add_test("test_pcr_nonos_kernel_config", constants::test_pcr_nonos_kernel_config);
    suite.add_test("test_pcr_nonos_ima", constants::test_pcr_nonos_ima);
    suite.add_test("test_pcr_nonos_modules", constants::test_pcr_nonos_modules);
    suite.add_test("test_tpm_st_no_sessions", constants::test_tpm_st_no_sessions);
    suite.add_test("test_tpm_st_sessions", constants::test_tpm_st_sessions);
    suite.add_test("test_tpm_rs_pw", constants::test_tpm_rs_pw);
    suite.add_test("test_tpm_rh_endorsement", constants::test_tpm_rh_endorsement);
    suite.add_test("test_locality_request_timeout", constants::test_locality_request_timeout);
    suite.add_test("test_command_ready_timeout", constants::test_command_ready_timeout);
    suite.add_test("test_response_timeout", constants::test_response_timeout);
    suite.add_test("test_tpm_buffer_size", constants::test_tpm_buffer_size);
    suite.add_test("test_tpm_max_random_bytes", constants::test_tpm_max_random_bytes);
    suite.add_test("test_tpm_max_digest_size", constants::test_tpm_max_digest_size);
    suite.add_test("test_tpm_num_pcrs", constants::test_tpm_num_pcrs);
    suite.add_test("test_ev_nonos_kernel", constants::test_ev_nonos_kernel);
    suite.add_test("test_ev_nonos_module", constants::test_ev_nonos_module);
    suite.add_test("test_ev_nonos_config", constants::test_ev_nonos_config);
    suite.add_test("test_tpm_max_commands_per_sec", constants::test_tpm_max_commands_per_sec);
    suite.add_test(
        "test_tpm_max_random_requests_per_sec",
        constants::test_tpm_max_random_requests_per_sec,
    );
    suite.add_test("test_locality_spacing", constants::test_locality_spacing);
    suite.add_test("test_pcr_ranges_valid", constants::test_pcr_ranges_valid);

    // error tests (37 tests)
    suite.add_test("test_error_not_initialized_str", error::test_error_not_initialized_str);
    suite.add_test("test_error_not_present_str", error::test_error_not_present_str);
    suite.add_test("test_error_timeout_str", error::test_error_timeout_str);
    suite.add_test("test_error_invalid_response_str", error::test_error_invalid_response_str);
    suite.add_test("test_error_locality_error_str", error::test_error_locality_error_str);
    suite.add_test("test_error_command_failed_str", error::test_error_command_failed_str);
    suite.add_test("test_error_buffer_too_small_str", error::test_error_buffer_too_small_str);
    suite.add_test("test_error_invalid_parameter_str", error::test_error_invalid_parameter_str);
    suite.add_test("test_error_auth_failed_str", error::test_error_auth_failed_str);
    suite.add_test("test_error_nv_error_str", error::test_error_nv_error_str);
    suite.add_test("test_error_pcr_error_str", error::test_error_pcr_error_str);
    suite.add_test("test_error_communication_error_str", error::test_error_communication_error_str);
    suite.add_test("test_error_hardware_error_str", error::test_error_hardware_error_str);
    suite.add_test("test_error_rate_limit_exceeded_str", error::test_error_rate_limit_exceeded_str);
    suite.add_test(
        "test_error_command_failed_response_code",
        error::test_error_command_failed_response_code,
    );
    suite.add_test(
        "test_error_timeout_response_code_none",
        error::test_error_timeout_response_code_none,
    );
    suite.add_test(
        "test_error_not_present_response_code_none",
        error::test_error_not_present_response_code_none,
    );
    suite.add_test("test_error_timeout_recoverable", error::test_error_timeout_recoverable);
    suite.add_test(
        "test_error_locality_error_recoverable",
        error::test_error_locality_error_recoverable,
    );
    suite.add_test(
        "test_error_buffer_too_small_recoverable",
        error::test_error_buffer_too_small_recoverable,
    );
    suite.add_test(
        "test_error_invalid_parameter_recoverable",
        error::test_error_invalid_parameter_recoverable,
    );
    suite.add_test(
        "test_error_rate_limit_exceeded_recoverable",
        error::test_error_rate_limit_exceeded_recoverable,
    );
    suite.add_test(
        "test_error_not_present_not_recoverable",
        error::test_error_not_present_not_recoverable,
    );
    suite.add_test(
        "test_error_hardware_error_not_recoverable",
        error::test_error_hardware_error_not_recoverable,
    );
    suite.add_test(
        "test_error_command_failed_not_recoverable",
        error::test_error_command_failed_not_recoverable,
    );
    suite.add_test("test_error_not_present_fatal", error::test_error_not_present_fatal);
    suite.add_test("test_error_hardware_error_fatal", error::test_error_hardware_error_fatal);
    suite.add_test("test_error_timeout_not_fatal", error::test_error_timeout_not_fatal);
    suite.add_test(
        "test_error_command_failed_not_fatal",
        error::test_error_command_failed_not_fatal,
    );
    suite.add_test("test_error_equality", error::test_error_equality);
    suite.add_test("test_error_command_failed_equality", error::test_error_command_failed_equality);
    suite.add_test("test_error_copy", error::test_error_copy);
    suite.add_test("test_error_clone", error::test_error_clone);
    suite.add_test("test_error_debug", error::test_error_debug);
    suite.add_test("test_error_display_timeout", error::test_error_display_timeout);
    suite.add_test("test_error_display_command_failed", error::test_error_display_command_failed);
    suite.add_test("test_all_errors_have_message", error::test_all_errors_have_message);

    // measurement tests (31 tests)
    suite.add_test(
        "test_component_type_bootloader_pcr",
        measurement::test_component_type_bootloader_pcr,
    );
    suite.add_test(
        "test_component_type_bootloader_config_pcr",
        measurement::test_component_type_bootloader_config_pcr,
    );
    suite.add_test(
        "test_component_type_kernel_code_pcr",
        measurement::test_component_type_kernel_code_pcr,
    );
    suite.add_test(
        "test_component_type_kernel_config_pcr",
        measurement::test_component_type_kernel_config_pcr,
    );
    suite.add_test("test_component_type_module_pcr", measurement::test_component_type_module_pcr);
    suite.add_test(
        "test_component_type_ima_policy_pcr",
        measurement::test_component_type_ima_policy_pcr,
    );
    suite.add_test(
        "test_component_type_bootloader_event",
        measurement::test_component_type_bootloader_event,
    );
    suite.add_test(
        "test_component_type_kernel_event",
        measurement::test_component_type_kernel_event,
    );
    suite.add_test(
        "test_component_type_module_event",
        measurement::test_component_type_module_event,
    );
    suite.add_test(
        "test_component_type_ima_policy_event",
        measurement::test_component_type_ima_policy_event,
    );
    suite.add_test(
        "test_component_type_bootloader_str",
        measurement::test_component_type_bootloader_str,
    );
    suite.add_test(
        "test_component_type_bootloader_config_str",
        measurement::test_component_type_bootloader_config_str,
    );
    suite.add_test(
        "test_component_type_kernel_code_str",
        measurement::test_component_type_kernel_code_str,
    );
    suite.add_test(
        "test_component_type_kernel_config_str",
        measurement::test_component_type_kernel_config_str,
    );
    suite.add_test("test_component_type_module_str", measurement::test_component_type_module_str);
    suite.add_test(
        "test_component_type_ima_policy_str",
        measurement::test_component_type_ima_policy_str,
    );
    suite.add_test("test_component_type_equality", measurement::test_component_type_equality);
    suite.add_test("test_component_type_copy", measurement::test_component_type_copy);
    suite.add_test("test_component_type_clone", measurement::test_component_type_clone);
    suite.add_test(
        "test_pcr_measurement_digest_len_sha1",
        measurement::test_pcr_measurement_digest_len_sha1,
    );
    suite.add_test(
        "test_pcr_measurement_digest_len_sha256",
        measurement::test_pcr_measurement_digest_len_sha256,
    );
    suite.add_test(
        "test_pcr_measurement_digest_len_sha384",
        measurement::test_pcr_measurement_digest_len_sha384,
    );
    suite.add_test(
        "test_pcr_measurement_digest_len_sha512",
        measurement::test_pcr_measurement_digest_len_sha512,
    );
    suite.add_test(
        "test_pcr_measurement_digest_len_unknown",
        measurement::test_pcr_measurement_digest_len_unknown,
    );
    suite.add_test("test_pcr_measurement_new", measurement::test_pcr_measurement_new);
    suite.add_test(
        "test_pcr_measurement_digest_slice",
        measurement::test_pcr_measurement_digest_slice,
    );
    suite.add_test(
        "test_pcr_measurement_truncates_large_digest",
        measurement::test_pcr_measurement_truncates_large_digest,
    );
    suite.add_test("test_pcr_measurement_clone", measurement::test_pcr_measurement_clone);
    suite.add_test(
        "test_boot_chain_measurements_new",
        measurement::test_boot_chain_measurements_new,
    );
    suite.add_test(
        "test_boot_chain_measurements_from_slices",
        measurement::test_boot_chain_measurements_from_slices,
    );
    suite.add_test(
        "test_boot_chain_measurements_clone",
        measurement::test_boot_chain_measurements_clone,
    );

    // status tests (27 tests)
    suite.add_test("test_tpm_status_not_present", status::test_tpm_status_not_present);
    suite.add_test("test_tpm_status_default", status::test_tpm_status_default);
    suite.add_test("test_tpm_status_vendor_id", status::test_tpm_status_vendor_id);
    suite.add_test("test_tpm_status_device_id", status::test_tpm_status_device_id);
    suite
        .add_test("test_tpm_status_manufacturer_intel", status::test_tpm_status_manufacturer_intel);
    suite.add_test("test_tpm_status_manufacturer_amd", status::test_tpm_status_manufacturer_amd);
    suite.add_test("test_tpm_status_manufacturer_ibm", status::test_tpm_status_manufacturer_ibm);
    suite.add_test(
        "test_tpm_status_manufacturer_infineon",
        status::test_tpm_status_manufacturer_infineon,
    );
    suite.add_test(
        "test_tpm_status_manufacturer_nuvoton",
        status::test_tpm_status_manufacturer_nuvoton,
    );
    suite.add_test(
        "test_tpm_status_manufacturer_unknown",
        status::test_tpm_status_manufacturer_unknown,
    );
    suite.add_test(
        "test_tpm_status_is_usable_when_present_and_init",
        status::test_tpm_status_is_usable_when_present_and_init,
    );
    suite.add_test(
        "test_tpm_status_not_usable_when_not_present",
        status::test_tpm_status_not_usable_when_not_present,
    );
    suite.add_test(
        "test_tpm_status_not_usable_when_not_initialized",
        status::test_tpm_status_not_usable_when_not_initialized,
    );
    suite.add_test("test_tpm_status_clone", status::test_tpm_status_clone);
    suite.add_test(
        "test_tpm_status_display_not_present",
        status::test_tpm_status_display_not_present,
    );
    suite.add_test(
        "test_tpm_status_display_not_initialized",
        status::test_tpm_status_display_not_initialized,
    );
    suite.add_test("test_pcr_bank_config_default", status::test_pcr_bank_config_default);
    suite.add_test("test_pcr_bank_config_sha256_only", status::test_pcr_bank_config_sha256_only);
    suite.add_test("test_pcr_bank_config_none", status::test_pcr_bank_config_none);
    suite.add_test(
        "test_pcr_bank_config_enabled_count_default",
        status::test_pcr_bank_config_enabled_count_default,
    );
    suite.add_test(
        "test_pcr_bank_config_enabled_count_sha256_only",
        status::test_pcr_bank_config_enabled_count_sha256_only,
    );
    suite.add_test(
        "test_pcr_bank_config_enabled_count_none",
        status::test_pcr_bank_config_enabled_count_none,
    );
    suite.add_test(
        "test_pcr_bank_config_enabled_count_all",
        status::test_pcr_bank_config_enabled_count_all,
    );
    suite.add_test("test_pcr_bank_config_copy", status::test_pcr_bank_config_copy);
    suite.add_test("test_pcr_bank_config_clone", status::test_pcr_bank_config_clone);

    suite.run()
}
