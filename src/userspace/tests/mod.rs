mod app_ui;
mod capability_assignment;
mod drivers_framework;
mod drivers_manager;
mod drivers_nvme;
mod drivers_pci;
mod drivers_virtio;
mod init_entry;
mod service_list;
mod service_runner;
mod spawn;
mod spawner;
mod supervisor;
mod wm;

use crate::test::framework::{TestCase, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("userspace");

    // Capability assignment tests (40)
    suite.add(TestCase::new("cap_vfs_is_bit_0", capability_assignment::test_cap_vfs_is_bit_0));
    suite.add(TestCase::new("cap_net_is_bit_1", capability_assignment::test_cap_net_is_bit_1));
    suite.add(TestCase::new(
        "cap_display_is_bit_2",
        capability_assignment::test_cap_display_is_bit_2,
    ));
    suite
        .add(TestCase::new("cap_driver_is_bit_3", capability_assignment::test_cap_driver_is_bit_3));
    suite
        .add(TestCase::new("cap_crypto_is_bit_4", capability_assignment::test_cap_crypto_is_bit_4));
    suite.add(TestCase::new(
        "cap_process_is_bit_5",
        capability_assignment::test_cap_process_is_bit_5,
    ));
    suite
        .add(TestCase::new("cap_memory_is_bit_6", capability_assignment::test_cap_memory_is_bit_6));
    suite.add(TestCase::new("cap_input_is_bit_7", capability_assignment::test_cap_input_is_bit_7));
    suite.add(TestCase::new("cap_audio_is_bit_8", capability_assignment::test_cap_audio_is_bit_8));
    suite.add(TestCase::new("cap_zk_is_bit_9", capability_assignment::test_cap_zk_is_bit_9));
    suite.add(TestCase::new("cap_gpu_is_bit_10", capability_assignment::test_cap_gpu_is_bit_10));
    suite.add(TestCase::new("cap_apps_is_bit_11", capability_assignment::test_cap_apps_is_bit_11));
    suite.add(TestCase::new(
        "cap_agents_is_bit_12",
        capability_assignment::test_cap_agents_is_bit_12,
    ));
    suite
        .add(TestCase::new("cap_shell_is_bit_13", capability_assignment::test_cap_shell_is_bit_13));
    suite
        .add(TestCase::new("cap_admin_is_bit_63", capability_assignment::test_cap_admin_is_bit_63));
    suite.add(TestCase::new("all_caps_unique", capability_assignment::test_all_caps_unique));
    suite.add(TestCase::new(
        "caps_are_powers_of_two",
        capability_assignment::test_caps_are_powers_of_two,
    ));
    suite.add(TestCase::new("caps_no_overlap", capability_assignment::test_caps_no_overlap));
    suite.add(TestCase::new("service_cap_new", capability_assignment::test_service_cap_new));
    suite.add(TestCase::new(
        "service_cap_with_expiry",
        capability_assignment::test_service_cap_with_expiry,
    ));
    suite.add(TestCase::new("service_cap_has", capability_assignment::test_service_cap_has));
    suite
        .add(TestCase::new("service_cap_has_all", capability_assignment::test_service_cap_has_all));
    suite.add(TestCase::new(
        "service_cap_has_partial",
        capability_assignment::test_service_cap_has_partial,
    ));
    suite.add(TestCase::new(
        "service_cap_is_expired_zero",
        capability_assignment::test_service_cap_is_expired_zero,
    ));
    suite.add(TestCase::new(
        "service_cap_is_expired_not_yet",
        capability_assignment::test_service_cap_is_expired_not_yet,
    ));
    suite.add(TestCase::new(
        "service_cap_is_expired_past",
        capability_assignment::test_service_cap_is_expired_past,
    ));
    suite.add(TestCase::new(
        "service_cap_is_expired_exact",
        capability_assignment::test_service_cap_is_expired_exact,
    ));
    suite.add(TestCase::new("service_cap_debug", capability_assignment::test_service_cap_debug));
    suite.add(TestCase::new("service_cap_clone", capability_assignment::test_service_cap_clone));
    suite.add(TestCase::new("service_cap_copy", capability_assignment::test_service_cap_copy));
    suite.add(TestCase::new(
        "service_cap_partial_eq",
        capability_assignment::test_service_cap_partial_eq,
    ));
    suite.add(TestCase::new(
        "service_cap_not_equal_different_bits",
        capability_assignment::test_service_cap_not_equal_different_bits,
    ));
    suite.add(TestCase::new(
        "service_cap_not_equal_different_owner",
        capability_assignment::test_service_cap_not_equal_different_owner,
    ));
    suite.add(TestCase::new(
        "vfs_service_gets_vfs_cap",
        capability_assignment::test_vfs_service_gets_vfs_cap,
    ));
    suite.add(TestCase::new(
        "network_service_gets_net_cap",
        capability_assignment::test_network_service_gets_net_cap,
    ));
    suite.add(TestCase::new(
        "display_service_gets_display_cap",
        capability_assignment::test_display_service_gets_display_cap,
    ));
    suite.add(TestCase::new(
        "crypto_service_gets_crypto_cap",
        capability_assignment::test_crypto_service_gets_crypto_cap,
    ));
    suite.add(TestCase::new(
        "desktop_service_gets_both_caps",
        capability_assignment::test_desktop_service_gets_both_caps,
    ));
    suite.add(TestCase::new(
        "services_get_only_needed_caps",
        capability_assignment::test_services_get_only_needed_caps,
    ));
    suite.add(TestCase::new(
        "unknown_service_gets_no_caps",
        capability_assignment::test_unknown_service_gets_no_caps,
    ));

    // Drivers framework tests (24)
    suite.add(TestCase::new("driver_op_init_value", drivers_framework::test_driver_op_init_value));
    suite.add(TestCase::new("driver_op_read_value", drivers_framework::test_driver_op_read_value));
    suite
        .add(TestCase::new("driver_op_write_value", drivers_framework::test_driver_op_write_value));
    suite
        .add(TestCase::new("driver_op_ioctl_value", drivers_framework::test_driver_op_ioctl_value));
    suite.add(TestCase::new(
        "driver_op_interrupt_value",
        drivers_framework::test_driver_op_interrupt_value,
    ));
    suite.add(TestCase::new(
        "driver_op_shutdown_value",
        drivers_framework::test_driver_op_shutdown_value,
    ));
    suite.add(TestCase::new("driver_op_debug", drivers_framework::test_driver_op_debug));
    suite.add(TestCase::new("driver_op_clone", drivers_framework::test_driver_op_clone));
    suite.add(TestCase::new("driver_op_copy", drivers_framework::test_driver_op_copy));
    suite.add(TestCase::new("driver_op_partial_eq", drivers_framework::test_driver_op_partial_eq));
    suite.add(TestCase::new("driver_op_eq", drivers_framework::test_driver_op_eq));
    suite.add(TestCase::new("driver_request_debug", drivers_framework::test_driver_request_debug));
    suite.add(TestCase::new("driver_request_clone", drivers_framework::test_driver_request_clone));
    suite
        .add(TestCase::new("driver_request_fields", drivers_framework::test_driver_request_fields));
    suite.add(TestCase::new(
        "driver_request_empty_data",
        drivers_framework::test_driver_request_empty_data,
    ));
    suite.add(TestCase::new("driver_response_ok", drivers_framework::test_driver_response_ok));
    suite.add(TestCase::new(
        "driver_response_ok_empty",
        drivers_framework::test_driver_response_ok_empty,
    ));
    suite.add(TestCase::new("driver_response_err", drivers_framework::test_driver_response_err));
    suite.add(TestCase::new(
        "driver_response_err_codes",
        drivers_framework::test_driver_response_err_codes,
    ));
    suite
        .add(TestCase::new("driver_response_debug", drivers_framework::test_driver_response_debug));
    suite
        .add(TestCase::new("driver_response_clone", drivers_framework::test_driver_response_clone));
    suite.add(TestCase::new(
        "driver_response_fields",
        drivers_framework::test_driver_response_fields,
    ));
    suite.add(TestCase::new(
        "driver_op_all_variants",
        drivers_framework::test_driver_op_all_variants,
    ));
    suite.add(TestCase::new(
        "driver_op_consecutive_values",
        drivers_framework::test_driver_op_consecutive_values,
    ));

    // Drivers manager tests (3)
    suite.add(TestCase::new("drivers_manager_module_exists", drivers_manager::test_module_exists));
    suite.add(TestCase::new(
        "drivers_manager_basic_constants",
        drivers_manager::test_basic_constants,
    ));
    suite.add(TestCase::new(
        "drivers_manager_basic_operations",
        drivers_manager::test_basic_operations,
    ));

    // Drivers NVMe tests (3)
    suite.add(TestCase::new("drivers_nvme_module_exists", drivers_nvme::test_module_exists));
    suite.add(TestCase::new("drivers_nvme_basic_constants", drivers_nvme::test_basic_constants));
    suite.add(TestCase::new("drivers_nvme_basic_operations", drivers_nvme::test_basic_operations));

    // Drivers PCI tests (3)
    suite.add(TestCase::new("drivers_pci_module_exists", drivers_pci::test_module_exists));
    suite.add(TestCase::new("drivers_pci_basic_constants", drivers_pci::test_basic_constants));
    suite.add(TestCase::new("drivers_pci_basic_operations", drivers_pci::test_basic_operations));

    // Drivers VirtIO tests (3)
    suite.add(TestCase::new("drivers_virtio_module_exists", drivers_virtio::test_module_exists));
    suite
        .add(TestCase::new("drivers_virtio_basic_constants", drivers_virtio::test_basic_constants));
    suite.add(TestCase::new(
        "drivers_virtio_basic_operations",
        drivers_virtio::test_basic_operations,
    ));

    // Init entry tests (18)
    suite.add(TestCase::new("core_services_not_empty", init_entry::test_core_services_not_empty));
    suite.add(TestCase::new(
        "driver_services_not_empty",
        init_entry::test_driver_services_not_empty,
    ));
    suite.add(TestCase::new(
        "core_services_contains_vfs",
        init_entry::test_core_services_contains_vfs,
    ));
    suite.add(TestCase::new(
        "core_services_contains_display",
        init_entry::test_core_services_contains_display,
    ));
    suite.add(TestCase::new(
        "core_services_contains_input",
        init_entry::test_core_services_contains_input,
    ));
    suite.add(TestCase::new(
        "core_services_contains_network",
        init_entry::test_core_services_contains_network,
    ));
    suite.add(TestCase::new(
        "core_services_contains_crypto",
        init_entry::test_core_services_contains_crypto,
    ));
    suite.add(TestCase::new(
        "core_services_contains_zk",
        init_entry::test_core_services_contains_zk,
    ));
    suite.add(TestCase::new(
        "core_services_contains_audio",
        init_entry::test_core_services_contains_audio,
    ));
    suite.add(TestCase::new(
        "core_services_contains_gpu",
        init_entry::test_core_services_contains_gpu,
    ));
    suite.add(TestCase::new(
        "core_services_contains_apps",
        init_entry::test_core_services_contains_apps,
    ));
    suite.add(TestCase::new(
        "core_services_contains_agents",
        init_entry::test_core_services_contains_agents,
    ));
    suite.add(TestCase::new(
        "core_services_contains_shell",
        init_entry::test_core_services_contains_shell,
    ));
    suite.add(TestCase::new(
        "core_services_contains_desktop",
        init_entry::test_core_services_contains_desktop,
    ));
    suite.add(TestCase::new(
        "driver_services_contains_drivers",
        init_entry::test_driver_services_contains_drivers,
    ));
    suite.add(TestCase::new("core_services_count", init_entry::test_core_services_count));
    suite.add(TestCase::new("driver_services_count", init_entry::test_driver_services_count));
    suite.add(TestCase::new("run_init_exported", init_entry::test_run_init_exported));

    // Service list tests (21)
    suite.add(TestCase::new(
        "core_services_is_static_slice",
        service_list::test_core_services_is_static_slice,
    ));
    suite.add(TestCase::new(
        "driver_services_is_static_slice",
        service_list::test_driver_services_is_static_slice,
    ));
    suite.add(TestCase::new(
        "core_services_first_is_vfs",
        service_list::test_core_services_first_is_vfs,
    ));
    suite.add(TestCase::new(
        "core_services_second_is_display",
        service_list::test_core_services_second_is_display,
    ));
    suite.add(TestCase::new(
        "core_services_third_is_input",
        service_list::test_core_services_third_is_input,
    ));
    suite.add(TestCase::new(
        "core_services_fourth_is_network",
        service_list::test_core_services_fourth_is_network,
    ));
    suite.add(TestCase::new(
        "core_services_fifth_is_crypto",
        service_list::test_core_services_fifth_is_crypto,
    ));
    suite.add(TestCase::new(
        "core_services_sixth_is_zk",
        service_list::test_core_services_sixth_is_zk,
    ));
    suite.add(TestCase::new(
        "core_services_seventh_is_audio",
        service_list::test_core_services_seventh_is_audio,
    ));
    suite.add(TestCase::new(
        "core_services_eighth_is_gpu",
        service_list::test_core_services_eighth_is_gpu,
    ));
    suite.add(TestCase::new(
        "core_services_ninth_is_apps",
        service_list::test_core_services_ninth_is_apps,
    ));
    suite.add(TestCase::new(
        "core_services_tenth_is_agents",
        service_list::test_core_services_tenth_is_agents,
    ));
    suite.add(TestCase::new(
        "core_services_eleventh_is_shell",
        service_list::test_core_services_eleventh_is_shell,
    ));
    suite.add(TestCase::new(
        "core_services_twelfth_is_desktop",
        service_list::test_core_services_twelfth_is_desktop,
    ));
    suite.add(TestCase::new(
        "driver_services_first_is_drivers",
        service_list::test_driver_services_first_is_drivers,
    ));
    suite.add(TestCase::new(
        "core_services_all_non_empty_strings",
        service_list::test_core_services_all_non_empty_strings,
    ));
    suite.add(TestCase::new(
        "driver_services_all_non_empty_strings",
        service_list::test_driver_services_all_non_empty_strings,
    ));
    suite.add(TestCase::new(
        "core_services_no_duplicates",
        service_list::test_core_services_no_duplicates,
    ));
    suite.add(TestCase::new(
        "driver_services_no_duplicates",
        service_list::test_driver_services_no_duplicates,
    ));
    suite.add(TestCase::new(
        "core_services_no_overlap_with_driver_services",
        service_list::test_core_services_no_overlap_with_driver_services,
    ));
    suite.add(TestCase::new("services_are_lowercase", service_list::test_services_are_lowercase));

    // Service runner tests (19)
    suite.add(TestCase::new(
        "run_vfs_service_exported",
        service_runner::test_run_vfs_service_exported,
    ));
    suite.add(TestCase::new(
        "run_net_service_exported",
        service_runner::test_run_net_service_exported,
    ));
    suite.add(TestCase::new(
        "run_display_service_exported",
        service_runner::test_run_display_service_exported,
    ));
    suite.add(TestCase::new(
        "run_driver_manager_exported",
        service_runner::test_run_driver_manager_exported,
    ));
    suite.add(TestCase::new(
        "run_crypto_service_exported",
        service_runner::test_run_crypto_service_exported,
    ));
    suite.add(TestCase::new(
        "run_zk_service_exported",
        service_runner::test_run_zk_service_exported,
    ));
    suite.add(TestCase::new(
        "run_input_service_exported",
        service_runner::test_run_input_service_exported,
    ));
    suite.add(TestCase::new(
        "run_audio_service_exported",
        service_runner::test_run_audio_service_exported,
    ));
    suite.add(TestCase::new(
        "run_gpu_service_exported",
        service_runner::test_run_gpu_service_exported,
    ));
    suite.add(TestCase::new(
        "run_apps_service_exported",
        service_runner::test_run_apps_service_exported,
    ));
    suite.add(TestCase::new(
        "run_agents_service_exported",
        service_runner::test_run_agents_service_exported,
    ));
    suite.add(TestCase::new(
        "run_shell_service_exported",
        service_runner::test_run_shell_service_exported,
    ));
    suite.add(TestCase::new(
        "run_service_by_name_exported",
        service_runner::test_run_service_by_name_exported,
    ));
    suite.add(TestCase::new(
        "service_runner_known_names",
        service_runner::test_service_runner_known_names,
    ));
    suite.add(TestCase::new(
        "service_names_all_lowercase",
        service_runner::test_service_names_all_lowercase,
    ));
    suite.add(TestCase::new(
        "service_names_no_whitespace",
        service_runner::test_service_names_no_whitespace,
    ));
    suite.add(TestCase::new(
        "all_services_have_run_function",
        service_runner::test_all_services_have_run_function,
    ));
    suite.add(TestCase::new("service_count", service_runner::test_service_count));
    suite.add(TestCase::new("services_are_unique", service_runner::test_services_are_unique));

    suite.add(TestCase::new(
        "wm_focus_policy_regression_markers",
        wm::test_wm_focus_policy_regression_markers,
    ));
    suite.add(TestCase::new(
        "wm_lifecycle_resize_regression_markers",
        wm::test_wm_lifecycle_resize_regression_markers,
    ));
    suite.add(TestCase::new(
        "about_app_exit_cleanup_markers",
        app_ui::test_about_app_exit_cleanup_markers,
    ));
    suite.add(TestCase::new(
        "about_app_no_global_mut_state",
        app_ui::test_about_app_no_global_mut_state,
    ));

    // Spawn tests (7)
    suite.add(TestCase::new("spawn_error_debug", spawn::test_spawn_error_debug));
    suite.add(TestCase::new("spawn_error_clone", spawn::test_spawn_error_clone));
    suite.add(TestCase::new("spawn_error_copy", spawn::test_spawn_error_copy));
    suite
        .add(TestCase::new("spawn_error_from_static_str", spawn::test_spawn_error_from_static_str));
    suite.add(TestCase::new("spawn_error_from_empty_str", spawn::test_spawn_error_from_empty_str));
    suite.add(TestCase::new("spawn_service_exported", spawn::test_spawn_service_exported));
    suite.add(TestCase::new(
        "spawn_error_is_failed_variant",
        spawn::test_spawn_error_is_failed_variant,
    ));

    // Spawner tests (3)
    suite.add(TestCase::new("spawner_module_exists", spawner::test_module_exists));
    suite.add(TestCase::new("spawner_basic_constants", spawner::test_basic_constants));
    suite.add(TestCase::new("spawner_basic_operations", spawner::test_basic_operations));

    // Supervisor tests (22)
    suite.add(TestCase::new("verify_interval_constant", supervisor::test_verify_interval_constant));
    suite.add(TestCase::new(
        "supervise_interval_constant",
        supervisor::test_supervise_interval_constant,
    ));
    suite.add(TestCase::new(
        "max_restart_attempts_constant",
        supervisor::test_max_restart_attempts_constant,
    ));
    suite.add(TestCase::new(
        "restart_backoff_base_constant",
        supervisor::test_restart_backoff_base_constant,
    ));
    suite.add(TestCase::new(
        "backoff_calculation_first_attempt",
        supervisor::test_backoff_calculation_first_attempt,
    ));
    suite.add(TestCase::new(
        "backoff_calculation_second_attempt",
        supervisor::test_backoff_calculation_second_attempt,
    ));
    suite.add(TestCase::new(
        "backoff_calculation_third_attempt",
        supervisor::test_backoff_calculation_third_attempt,
    ));
    suite.add(TestCase::new(
        "backoff_calculation_fourth_attempt",
        supervisor::test_backoff_calculation_fourth_attempt,
    ));
    suite.add(TestCase::new(
        "backoff_calculation_fifth_attempt",
        supervisor::test_backoff_calculation_fifth_attempt,
    ));
    suite.add(TestCase::new(
        "backoff_capped_at_16_seconds",
        supervisor::test_backoff_capped_at_16_seconds,
    ));
    suite.add(TestCase::new(
        "backoff_capped_at_max_attempts",
        supervisor::test_backoff_capped_at_max_attempts,
    ));
    suite.add(TestCase::new(
        "verify_interval_is_5x_supervise",
        supervisor::test_verify_interval_is_5x_supervise,
    ));
    suite.add(TestCase::new(
        "all_core_services_supervised",
        supervisor::test_all_core_services_supervised,
    ));
    suite.add(TestCase::new(
        "supervision_uses_core_services_list",
        supervisor::test_supervision_uses_core_services_list,
    ));
    suite.add(TestCase::new(
        "verification_uses_core_services_list",
        supervisor::test_verification_uses_core_services_list,
    ));
    suite.add(TestCase::new(
        "restart_state_entry_creation",
        supervisor::test_restart_state_entry_creation,
    ));
    suite.add(TestCase::new("restart_info_increment", supervisor::test_restart_info_increment));
    suite.add(TestCase::new(
        "max_restarts_prevents_restart",
        supervisor::test_max_restarts_prevents_restart,
    ));
    suite.add(TestCase::new(
        "under_max_restarts_allows_restart",
        supervisor::test_under_max_restarts_allows_restart,
    ));
    suite.add(TestCase::new("backoff_progression", supervisor::test_backoff_progression));
    suite.add(TestCase::new(
        "supervisor_loop_constants_positive",
        supervisor::test_supervisor_loop_constants_positive,
    ));
    suite.add(TestCase::new(
        "driver_services_not_in_core_supervision",
        supervisor::test_driver_services_not_in_core_supervision,
    ));

    suite.run()
}
