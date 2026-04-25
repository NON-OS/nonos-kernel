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
pub mod descriptors;
pub mod error;
pub mod hid;
pub mod hub;
pub mod msc;

use crate::test::framework::TestSuite;

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("usb");

    // constants tests - using actual function names from constants.rs
    suite.add_test("test_request_get_status", constants::test_request_get_status);
    suite.add_test("test_request_clear_feature", constants::test_request_clear_feature);
    suite.add_test("test_request_set_feature", constants::test_request_set_feature);
    suite.add_test("test_request_set_address", constants::test_request_set_address);
    suite.add_test("test_request_get_descriptor", constants::test_request_get_descriptor);
    suite.add_test("test_request_set_descriptor", constants::test_request_set_descriptor);
    suite.add_test("test_request_get_configuration", constants::test_request_get_configuration);
    suite.add_test("test_request_set_configuration", constants::test_request_set_configuration);
    suite.add_test("test_request_get_interface", constants::test_request_get_interface);
    suite.add_test("test_request_set_interface", constants::test_request_set_interface);
    suite.add_test("test_request_synch_frame", constants::test_request_synch_frame);
    suite.add_test("test_recipient_device", constants::test_recipient_device);
    suite.add_test("test_recipient_interface", constants::test_recipient_interface);
    suite.add_test("test_recipient_endpoint", constants::test_recipient_endpoint);
    suite.add_test("test_recipient_other", constants::test_recipient_other);
    suite.add_test("test_direction_out", constants::test_direction_out);
    suite.add_test("test_direction_in", constants::test_direction_in);
    suite.add_test("test_type_standard", constants::test_type_standard);
    suite.add_test("test_type_class", constants::test_type_class);
    suite.add_test("test_type_vendor", constants::test_type_vendor);
    suite.add_test("test_descriptor_type_device", constants::test_descriptor_type_device);
    suite.add_test("test_descriptor_type_config", constants::test_descriptor_type_config);
    suite.add_test("test_descriptor_type_string", constants::test_descriptor_type_string);
    suite.add_test("test_descriptor_type_interface", constants::test_descriptor_type_interface);
    suite.add_test("test_descriptor_type_endpoint", constants::test_descriptor_type_endpoint);
    suite.add_test(
        "test_descriptor_type_device_qualifier",
        constants::test_descriptor_type_device_qualifier,
    );
    suite.add_test(
        "test_descriptor_type_other_speed_config",
        constants::test_descriptor_type_other_speed_config,
    );
    suite.add_test(
        "test_descriptor_type_interface_power",
        constants::test_descriptor_type_interface_power,
    );
    suite.add_test("test_descriptor_type_otg", constants::test_descriptor_type_otg);
    suite.add_test("test_descriptor_type_debug", constants::test_descriptor_type_debug);
    suite.add_test(
        "test_descriptor_type_interface_assoc",
        constants::test_descriptor_type_interface_assoc,
    );
    suite.add_test("test_descriptor_type_bos", constants::test_descriptor_type_bos);
    suite.add_test(
        "test_descriptor_type_device_capability",
        constants::test_descriptor_type_device_capability,
    );
    suite.add_test(
        "test_descriptor_type_ss_ep_companion",
        constants::test_descriptor_type_ss_ep_companion,
    );
    suite.add_test(
        "test_descriptor_type_ssp_isoch_ep_companion",
        constants::test_descriptor_type_ssp_isoch_ep_companion,
    );
    suite.add_test("test_endpoint_transfer_type_mask", constants::test_endpoint_transfer_type_mask);
    suite.add_test("test_endpoint_type_control", constants::test_endpoint_type_control);
    suite.add_test("test_endpoint_type_isochronous", constants::test_endpoint_type_isochronous);
    suite.add_test("test_endpoint_type_bulk", constants::test_endpoint_type_bulk);
    suite.add_test("test_endpoint_type_interrupt", constants::test_endpoint_type_interrupt);
    suite.add_test("test_endpoint_sync_type_mask", constants::test_endpoint_sync_type_mask);
    suite.add_test("test_endpoint_sync_none", constants::test_endpoint_sync_none);
    suite.add_test("test_endpoint_sync_async", constants::test_endpoint_sync_async);
    suite.add_test("test_endpoint_sync_adaptive", constants::test_endpoint_sync_adaptive);
    suite.add_test("test_endpoint_sync_sync", constants::test_endpoint_sync_sync);
    suite.add_test("test_endpoint_usage_type_mask", constants::test_endpoint_usage_type_mask);
    suite.add_test("test_endpoint_usage_data", constants::test_endpoint_usage_data);
    suite.add_test("test_endpoint_usage_feedback", constants::test_endpoint_usage_feedback);
    suite.add_test("test_endpoint_usage_implicit_fb", constants::test_endpoint_usage_implicit_fb);
    suite.add_test("test_class_device", constants::test_class_device);
    suite.add_test("test_class_audio", constants::test_class_audio);
    suite.add_test("test_class_cdc", constants::test_class_cdc);
    suite.add_test("test_class_hid", constants::test_class_hid);
    suite.add_test("test_class_physical", constants::test_class_physical);
    suite.add_test("test_class_image", constants::test_class_image);
    suite.add_test("test_class_printer", constants::test_class_printer);
    suite.add_test("test_class_mass_storage", constants::test_class_mass_storage);
    suite.add_test("test_class_hub", constants::test_class_hub);
    suite.add_test("test_class_cdc_data", constants::test_class_cdc_data);
    suite.add_test("test_class_smart_card", constants::test_class_smart_card);
    suite.add_test("test_class_content_security", constants::test_class_content_security);
    suite.add_test("test_class_video", constants::test_class_video);
    suite.add_test("test_class_personal_healthcare", constants::test_class_personal_healthcare);
    suite.add_test("test_class_audio_video", constants::test_class_audio_video);
    suite.add_test("test_class_billboard", constants::test_class_billboard);
    suite.add_test("test_class_type_c_bridge", constants::test_class_type_c_bridge);
    suite.add_test("test_class_diagnostic", constants::test_class_diagnostic);
    suite.add_test("test_class_wireless", constants::test_class_wireless);
    suite.add_test("test_class_misc", constants::test_class_misc);
    suite.add_test("test_class_application", constants::test_class_application);
    suite.add_test("test_class_vendor", constants::test_class_vendor);
    suite.add_test("test_feature_endpoint_halt", constants::test_feature_endpoint_halt);
    suite.add_test(
        "test_feature_device_remote_wakeup",
        constants::test_feature_device_remote_wakeup,
    );
    suite.add_test("test_feature_test_mode", constants::test_feature_test_mode);
    suite.add_test("test_default_control_timeout", constants::test_default_control_timeout);
    suite.add_test("test_default_bulk_timeout", constants::test_default_bulk_timeout);
    suite.add_test("test_default_interrupt_timeout", constants::test_default_interrupt_timeout);
    suite.add_test("test_usb2_max_control_packet", constants::test_usb2_max_control_packet);
    suite.add_test("test_usb3_max_control_packet", constants::test_usb3_max_control_packet);
    suite.add_test("test_default_lang_id", constants::test_default_lang_id);
    suite.add_test("test_timeout_ordering", constants::test_timeout_ordering);

    // descriptors tests
    suite.add_test("test_device_descriptor_size", descriptors::test_device_descriptor_size);
    suite.add_test(
        "test_config_descriptor_header_size",
        descriptors::test_config_descriptor_header_size,
    );
    suite.add_test("test_interface_descriptor_size", descriptors::test_interface_descriptor_size);
    suite.add_test("test_endpoint_descriptor_size", descriptors::test_endpoint_descriptor_size);
    suite.add_test(
        "test_endpoint_descriptor_in_direction",
        descriptors::test_endpoint_descriptor_in_direction,
    );
    suite.add_test(
        "test_endpoint_descriptor_out_direction",
        descriptors::test_endpoint_descriptor_out_direction,
    );
    suite.add_test("test_endpoint_descriptor_number", descriptors::test_endpoint_descriptor_number);
    suite.add_test(
        "test_endpoint_descriptor_bulk_type",
        descriptors::test_endpoint_descriptor_bulk_type,
    );
    suite.add_test(
        "test_endpoint_descriptor_interrupt_type",
        descriptors::test_endpoint_descriptor_interrupt_type,
    );
    suite.add_test(
        "test_endpoint_descriptor_control_type",
        descriptors::test_endpoint_descriptor_control_type,
    );
    suite.add_test(
        "test_endpoint_descriptor_isochronous_type",
        descriptors::test_endpoint_descriptor_isochronous_type,
    );
    suite.add_test(
        "test_endpoint_descriptor_max_packet_size",
        descriptors::test_endpoint_descriptor_max_packet_size,
    );
    suite.add_test(
        "test_endpoint_descriptor_transfer_type_name_control",
        descriptors::test_endpoint_descriptor_transfer_type_name_control,
    );
    suite.add_test(
        "test_endpoint_descriptor_transfer_type_name_bulk",
        descriptors::test_endpoint_descriptor_transfer_type_name_bulk,
    );
    suite.add_test(
        "test_endpoint_descriptor_transfer_type_name_interrupt",
        descriptors::test_endpoint_descriptor_transfer_type_name_interrupt,
    );
    suite.add_test(
        "test_endpoint_descriptor_transfer_type_name_isochronous",
        descriptors::test_endpoint_descriptor_transfer_type_name_isochronous,
    );
    suite.add_test("test_string_table_new", descriptors::test_string_table_new);
    suite.add_test(
        "test_string_table_display_name_empty",
        descriptors::test_string_table_display_name_empty,
    );
    suite.add_test("test_endpoint_number_range", descriptors::test_endpoint_number_range);
    suite.add_test("test_endpoint_direction_mask", descriptors::test_endpoint_direction_mask);

    // error tests
    suite.add_test(
        "test_error_as_str_controller_not_found",
        error::test_error_as_str_controller_not_found,
    );
    suite.add_test(
        "test_error_as_str_initialization_failed",
        error::test_error_as_str_initialization_failed,
    );
    suite.add_test("test_error_as_str_device_not_found", error::test_error_as_str_device_not_found);
    suite.add_test(
        "test_error_as_str_endpoint_not_found",
        error::test_error_as_str_endpoint_not_found,
    );
    suite.add_test("test_error_as_str_transfer_failed", error::test_error_as_str_transfer_failed);
    suite.add_test("test_error_as_str_transfer_timeout", error::test_error_as_str_transfer_timeout);
    suite.add_test("test_error_as_str_transfer_stall", error::test_error_as_str_transfer_stall);
    suite.add_test("test_error_as_str_transfer_babble", error::test_error_as_str_transfer_babble);
    suite.add_test("test_error_as_str_buffer_overrun", error::test_error_as_str_buffer_overrun);
    suite.add_test("test_error_as_str_buffer_underrun", error::test_error_as_str_buffer_underrun);
    suite.add_test(
        "test_error_as_str_invalid_descriptor",
        error::test_error_as_str_invalid_descriptor,
    );
    suite.add_test(
        "test_error_as_str_invalid_configuration",
        error::test_error_as_str_invalid_configuration,
    );
    suite.add_test(
        "test_error_as_str_invalid_interface",
        error::test_error_as_str_invalid_interface,
    );
    suite.add_test("test_error_as_str_invalid_endpoint", error::test_error_as_str_invalid_endpoint);
    suite.add_test(
        "test_error_as_str_unsupported_device",
        error::test_error_as_str_unsupported_device,
    );
    suite.add_test(
        "test_error_as_str_unsupported_class",
        error::test_error_as_str_unsupported_class,
    );
    suite.add_test("test_error_as_str_port_error", error::test_error_as_str_port_error);
    suite.add_test("test_error_as_str_reset_failed", error::test_error_as_str_reset_failed);
    suite.add_test(
        "test_error_as_str_enumeration_failed",
        error::test_error_as_str_enumeration_failed,
    );
    suite.add_test("test_error_as_str_dma_error", error::test_error_as_str_dma_error);
    suite.add_test(
        "test_error_as_str_command_ring_full",
        error::test_error_as_str_command_ring_full,
    );
    suite.add_test("test_error_as_str_event_ring_empty", error::test_error_as_str_event_ring_empty);
    suite.add_test("test_error_as_str_slot_not_enabled", error::test_error_as_str_slot_not_enabled);
    suite.add_test("test_error_as_str_context_error", error::test_error_as_str_context_error);
    suite.add_test("test_error_is_recoverable_timeout", error::test_error_is_recoverable_timeout);
    suite.add_test("test_error_is_recoverable_stall", error::test_error_is_recoverable_stall);
    suite.add_test(
        "test_error_is_recoverable_command_ring_full",
        error::test_error_is_recoverable_command_ring_full,
    );
    suite.add_test(
        "test_error_is_recoverable_event_ring_empty",
        error::test_error_is_recoverable_event_ring_empty,
    );
    suite.add_test(
        "test_error_is_not_recoverable_controller_not_found",
        error::test_error_is_not_recoverable_controller_not_found,
    );
    suite.add_test(
        "test_error_is_not_recoverable_device_not_found",
        error::test_error_is_not_recoverable_device_not_found,
    );
    suite.add_test(
        "test_error_is_not_recoverable_initialization_failed",
        error::test_error_is_not_recoverable_initialization_failed,
    );
    suite.add_test(
        "test_error_is_not_recoverable_dma_error",
        error::test_error_is_not_recoverable_dma_error,
    );
    suite.add_test("test_error_equality", error::test_error_equality);
    suite.add_test("test_error_copy", error::test_error_copy);
    suite.add_test("test_error_clone", error::test_error_clone);
    suite.add_test("test_error_debug", error::test_error_debug);
    suite.add_test("test_error_display", error::test_error_display);
    suite.add_test(
        "test_all_error_variants_have_message",
        error::test_all_error_variants_have_message,
    );
    suite.add_test("test_error_variant_count", error::test_error_variant_count);

    // hid tests
    suite.add_test("test_hid_subclass_none", hid::test_hid_subclass_none);
    suite.add_test("test_hid_subclass_boot", hid::test_hid_subclass_boot);
    suite.add_test("test_hid_protocol_none", hid::test_hid_protocol_none);
    suite.add_test("test_hid_protocol_keyboard", hid::test_hid_protocol_keyboard);
    suite.add_test("test_hid_protocol_mouse", hid::test_hid_protocol_mouse);
    suite.add_test("test_hid_descriptor_type_hid", hid::test_hid_descriptor_type_hid);
    suite.add_test("test_hid_descriptor_type_report", hid::test_hid_descriptor_type_report);
    suite.add_test("test_hid_descriptor_type_physical", hid::test_hid_descriptor_type_physical);
    suite.add_test("test_hid_request_get_report", hid::test_hid_request_get_report);
    suite.add_test("test_hid_request_get_idle", hid::test_hid_request_get_idle);
    suite.add_test("test_hid_request_get_protocol", hid::test_hid_request_get_protocol);
    suite.add_test("test_hid_request_set_report", hid::test_hid_request_set_report);
    suite.add_test("test_hid_request_set_idle", hid::test_hid_request_set_idle);
    suite.add_test("test_hid_request_set_protocol", hid::test_hid_request_set_protocol);
    suite.add_test("test_hid_report_type_input", hid::test_hid_report_type_input);
    suite.add_test("test_hid_report_type_output", hid::test_hid_report_type_output);
    suite.add_test("test_hid_report_type_feature", hid::test_hid_report_type_feature);
    suite.add_test("test_hid_boot_protocol", hid::test_hid_boot_protocol);
    suite.add_test("test_hid_report_protocol", hid::test_hid_report_protocol);
    suite.add_test("test_boot_keyboard_report_size", hid::test_boot_keyboard_report_size);
    suite.add_test("test_boot_mouse_report_size", hid::test_boot_mouse_report_size);
    suite.add_test("test_keyboard_led_num_lock", hid::test_keyboard_led_num_lock);
    suite.add_test("test_keyboard_led_caps_lock", hid::test_keyboard_led_caps_lock);
    suite.add_test("test_keyboard_led_scroll_lock", hid::test_keyboard_led_scroll_lock);
    suite.add_test("test_keyboard_led_compose", hid::test_keyboard_led_compose);
    suite.add_test("test_keyboard_led_kana", hid::test_keyboard_led_kana);
    suite.add_test("test_modifier_left_ctrl", hid::test_modifier_left_ctrl);
    suite.add_test("test_modifier_left_shift", hid::test_modifier_left_shift);
    suite.add_test("test_modifier_left_alt", hid::test_modifier_left_alt);
    suite.add_test("test_modifier_left_gui", hid::test_modifier_left_gui);
    suite.add_test("test_modifier_right_ctrl", hid::test_modifier_right_ctrl);
    suite.add_test("test_modifier_right_shift", hid::test_modifier_right_shift);
    suite.add_test("test_modifier_right_alt", hid::test_modifier_right_alt);
    suite.add_test("test_modifier_right_gui", hid::test_modifier_right_gui);
    suite.add_test("test_mouse_button_left", hid::test_mouse_button_left);
    suite.add_test("test_mouse_button_right", hid::test_mouse_button_right);
    suite.add_test("test_mouse_button_middle", hid::test_mouse_button_middle);
    suite.add_test("test_max_hid_devices", hid::test_max_hid_devices);
    suite.add_test("test_hid_poll_interval", hid::test_hid_poll_interval);
    suite.add_test("test_modifier_bits_unique", hid::test_modifier_bits_unique);
    suite.add_test("test_led_bits_unique", hid::test_led_bits_unique);
    suite.add_test("test_mouse_button_bits_unique", hid::test_mouse_button_bits_unique);

    // hub tests
    suite.add_test("test_hub_descriptor_type", hub::test_hub_descriptor_type);
    suite.add_test("test_ss_hub_descriptor_type", hub::test_ss_hub_descriptor_type);
    suite.add_test("test_hub_request_get_status", hub::test_hub_request_get_status);
    suite.add_test("test_hub_request_clear_feature", hub::test_hub_request_clear_feature);
    suite.add_test("test_hub_request_set_feature", hub::test_hub_request_set_feature);
    suite.add_test("test_hub_request_get_descriptor", hub::test_hub_request_get_descriptor);
    suite.add_test("test_hub_request_set_descriptor", hub::test_hub_request_set_descriptor);
    suite.add_test("test_hub_request_clear_tt_buffer", hub::test_hub_request_clear_tt_buffer);
    suite.add_test("test_hub_request_reset_tt", hub::test_hub_request_reset_tt);
    suite.add_test("test_hub_request_get_tt_state", hub::test_hub_request_get_tt_state);
    suite.add_test("test_hub_request_stop_tt", hub::test_hub_request_stop_tt);
    suite.add_test("test_hub_feature_local_power", hub::test_hub_feature_local_power);
    suite.add_test("test_hub_feature_over_current", hub::test_hub_feature_over_current);
    suite.add_test("test_port_feature_connection", hub::test_port_feature_connection);
    suite.add_test("test_port_feature_enable", hub::test_port_feature_enable);
    suite.add_test("test_port_feature_suspend", hub::test_port_feature_suspend);
    suite.add_test("test_port_feature_over_current", hub::test_port_feature_over_current);
    suite.add_test("test_port_feature_reset", hub::test_port_feature_reset);
    suite.add_test("test_port_feature_power", hub::test_port_feature_power);
    suite.add_test("test_port_feature_lowspeed", hub::test_port_feature_lowspeed);
    suite.add_test("test_port_feature_c_connection", hub::test_port_feature_c_connection);
    suite.add_test("test_port_feature_c_enable", hub::test_port_feature_c_enable);
    suite.add_test("test_port_feature_c_suspend", hub::test_port_feature_c_suspend);
    suite.add_test("test_port_feature_c_over_current", hub::test_port_feature_c_over_current);
    suite.add_test("test_port_feature_c_reset", hub::test_port_feature_c_reset);
    suite.add_test("test_port_status_connection", hub::test_port_status_connection);
    suite.add_test("test_port_status_enable", hub::test_port_status_enable);
    suite.add_test("test_port_status_suspend", hub::test_port_status_suspend);
    suite.add_test("test_port_status_overcurrent", hub::test_port_status_overcurrent);
    suite.add_test("test_port_status_reset", hub::test_port_status_reset);
    suite.add_test("test_port_status_power", hub::test_port_status_power);
    suite.add_test("test_port_status_low_speed", hub::test_port_status_low_speed);
    suite.add_test("test_port_status_high_speed", hub::test_port_status_high_speed);
    suite.add_test("test_port_status_test", hub::test_port_status_test);
    suite.add_test("test_port_status_indicator", hub::test_port_status_indicator);
    suite.add_test("test_hub_char_lpsm_mask", hub::test_hub_char_lpsm_mask);
    suite.add_test("test_hub_char_compound", hub::test_hub_char_compound);
    suite.add_test("test_hub_char_ocpm_mask", hub::test_hub_char_ocpm_mask);
    suite.add_test("test_hub_char_tttt_mask", hub::test_hub_char_tttt_mask);
    suite.add_test("test_hub_char_portind", hub::test_hub_char_portind);
    suite.add_test("test_max_hub_ports", hub::test_max_hub_ports);
    suite.add_test("test_hub_debounce_ms", hub::test_hub_debounce_ms);
    suite.add_test("test_hub_reset_ms", hub::test_hub_reset_ms);
    suite.add_test("test_hub_power_on_delay_ms", hub::test_hub_power_on_delay_ms);
    suite.add_test("test_feat_port_power", hub::test_feat_port_power);
    suite.add_test("test_feat_port_reset", hub::test_feat_port_reset);
    suite.add_test("test_feat_port_enable", hub::test_feat_port_enable);
    suite.add_test("test_feat_c_port_connection", hub::test_feat_c_port_connection);
    suite.add_test("test_port_status_bits_unique", hub::test_port_status_bits_unique);

    // msc tests
    suite.add_test("test_module_exists", msc::test_module_exists);
    suite.add_test("test_basic_constants", msc::test_basic_constants);
    suite.add_test("test_basic_operations", msc::test_basic_operations);

    suite.run()
}
