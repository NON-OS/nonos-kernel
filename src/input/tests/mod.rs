mod descriptor;
mod i2c_hid;
mod input_manager;
mod keyboard;
mod mouse;
mod touchpad;
mod usb_hid;

use crate::test::framework::{TestCase, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("input");

    // Descriptor tests (29)
    suite.add(TestCase::new("hid_descriptor_default", descriptor::test_hid_descriptor_default));
    suite.add(TestCase::new(
        "hid_descriptor_parse_valid",
        descriptor::test_hid_descriptor_parse_valid,
    ));
    suite.add(TestCase::new(
        "hid_descriptor_parse_too_short",
        descriptor::test_hid_descriptor_parse_too_short,
    ));
    suite.add(TestCase::new(
        "hid_descriptor_parse_invalid_length",
        descriptor::test_hid_descriptor_parse_invalid_length,
    ));
    suite.add(TestCase::new(
        "hid_descriptor_parse_invalid_version",
        descriptor::test_hid_descriptor_parse_invalid_version,
    ));
    suite.add(TestCase::new("field_location_default", descriptor::test_field_location_default));
    suite.add(TestCase::new("field_location_is_valid", descriptor::test_field_location_is_valid));
    suite.add(TestCase::new(
        "field_location_extract_single_bit",
        descriptor::test_field_location_extract_single_bit,
    ));
    suite.add(TestCase::new(
        "field_location_extract_single_bit_offset",
        descriptor::test_field_location_extract_single_bit_offset,
    ));
    suite.add(TestCase::new(
        "field_location_extract_byte_aligned",
        descriptor::test_field_location_extract_byte_aligned,
    ));
    suite.add(TestCase::new(
        "field_location_extract_16bit_aligned",
        descriptor::test_field_location_extract_16bit_aligned,
    ));
    suite.add(TestCase::new(
        "field_location_extract_empty_data",
        descriptor::test_field_location_extract_empty_data,
    ));
    suite.add(TestCase::new(
        "field_location_extract_invalid",
        descriptor::test_field_location_extract_invalid,
    ));
    suite.add(TestCase::new(
        "field_location_extract_out_of_bounds",
        descriptor::test_field_location_extract_out_of_bounds,
    ));
    suite.add(TestCase::new("contact_fields_default", descriptor::test_contact_fields_default));
    suite.add(TestCase::new("contact_fields_structure", descriptor::test_contact_fields_structure));
    suite.add(TestCase::new("touchpad_layout_default", descriptor::test_touchpad_layout_default));
    suite.add(TestCase::new(
        "touchpad_layout_contacts_array",
        descriptor::test_touchpad_layout_contacts_array,
    ));
    suite.add(TestCase::new("field_location_clone", descriptor::test_field_location_clone));
    suite.add(TestCase::new("field_location_copy", descriptor::test_field_location_copy));
    suite.add(TestCase::new("contact_fields_clone", descriptor::test_contact_fields_clone));
    suite.add(TestCase::new("hid_descriptor_clone", descriptor::test_hid_descriptor_clone));
    suite.add(TestCase::new("touchpad_layout_clone", descriptor::test_touchpad_layout_clone));
    suite.add(TestCase::new(
        "field_location_extract_multi_byte",
        descriptor::test_field_location_extract_multi_byte,
    ));
    suite.add(TestCase::new(
        "field_location_extract_nibble",
        descriptor::test_field_location_extract_nibble,
    ));
    suite.add(TestCase::new("field_location_bit_7", descriptor::test_field_location_bit_7));
    suite.add(TestCase::new("hid_descriptor_registers", descriptor::test_hid_descriptor_registers));
    suite.add(TestCase::new(
        "touchpad_layout_structure",
        descriptor::test_touchpad_layout_structure,
    ));

    // I2C HID tests (39)
    suite.add(TestCase::new("hid_command_reset", i2c_hid::test_hid_command_reset));
    suite.add(TestCase::new("hid_command_get_report", i2c_hid::test_hid_command_get_report));
    suite.add(TestCase::new("hid_command_set_report", i2c_hid::test_hid_command_set_report));
    suite.add(TestCase::new("hid_command_get_idle", i2c_hid::test_hid_command_get_idle));
    suite.add(TestCase::new("hid_command_set_idle", i2c_hid::test_hid_command_set_idle));
    suite.add(TestCase::new("hid_command_get_protocol", i2c_hid::test_hid_command_get_protocol));
    suite.add(TestCase::new("hid_command_set_protocol", i2c_hid::test_hid_command_set_protocol));
    suite.add(TestCase::new("hid_command_set_power", i2c_hid::test_hid_command_set_power));
    suite.add(TestCase::new("hid_command_clone", i2c_hid::test_hid_command_clone));
    suite.add(TestCase::new("hid_command_copy", i2c_hid::test_hid_command_copy));
    suite.add(TestCase::new("hid_command_equality", i2c_hid::test_hid_command_equality));
    suite.add(TestCase::new("hid_command_debug", i2c_hid::test_hid_command_debug));
    suite.add(TestCase::new("hid_register_hid_desc", i2c_hid::test_hid_register_hid_desc));
    suite.add(TestCase::new("hid_register_new", i2c_hid::test_hid_register_new));
    suite.add(TestCase::new("hid_register_to_le_bytes", i2c_hid::test_hid_register_to_le_bytes));
    suite.add(TestCase::new(
        "hid_register_to_le_bytes_zero",
        i2c_hid::test_hid_register_to_le_bytes_zero,
    ));
    suite.add(TestCase::new(
        "hid_register_to_le_bytes_max",
        i2c_hid::test_hid_register_to_le_bytes_max,
    ));
    suite.add(TestCase::new("hid_register_clone", i2c_hid::test_hid_register_clone));
    suite.add(TestCase::new("hid_register_copy", i2c_hid::test_hid_register_copy));
    suite.add(TestCase::new("hid_register_debug", i2c_hid::test_hid_register_debug));
    suite.add(TestCase::new("supported_commands_count", i2c_hid::test_supported_commands_count));
    suite.add(TestCase::new(
        "supported_commands_contains_reset",
        i2c_hid::test_supported_commands_contains_reset,
    ));
    suite.add(TestCase::new(
        "supported_commands_contains_get_report",
        i2c_hid::test_supported_commands_contains_get_report,
    ));
    suite.add(TestCase::new(
        "supported_commands_contains_set_report",
        i2c_hid::test_supported_commands_contains_set_report,
    ));
    suite.add(TestCase::new(
        "supported_commands_contains_set_power",
        i2c_hid::test_supported_commands_contains_set_power,
    ));
    suite.add(TestCase::new("hid_usage_page_digitizer", i2c_hid::test_hid_usage_page_digitizer));
    suite.add(TestCase::new(
        "hid_usage_page_generic_desktop",
        i2c_hid::test_hid_usage_page_generic_desktop,
    ));
    suite.add(TestCase::new("hid_usage_page_button", i2c_hid::test_hid_usage_page_button));
    suite.add(TestCase::new("hid_usage_touchpad", i2c_hid::test_hid_usage_touchpad));
    suite.add(TestCase::new("hid_usage_touch_screen", i2c_hid::test_hid_usage_touch_screen));
    suite.add(TestCase::new("hid_usage_mouse", i2c_hid::test_hid_usage_mouse));
    suite.add(TestCase::new("hid_usage_keyboard", i2c_hid::test_hid_usage_keyboard));
    suite.add(TestCase::new("hid_usage_tip_switch", i2c_hid::test_hid_usage_tip_switch));
    suite.add(TestCase::new("hid_usage_contact_id", i2c_hid::test_hid_usage_contact_id));
    suite.add(TestCase::new("hid_usage_x", i2c_hid::test_hid_usage_x));
    suite.add(TestCase::new("hid_usage_y", i2c_hid::test_hid_usage_y));
    suite.add(TestCase::new("hid_usage_contact_count", i2c_hid::test_hid_usage_contact_count));
    suite.add(TestCase::new("hid_usage_button_primary", i2c_hid::test_hid_usage_button_primary));
    suite
        .add(TestCase::new("hid_usage_button_secondary", i2c_hid::test_hid_usage_button_secondary));
    suite.add(TestCase::new(
        "all_hid_commands_have_unique_opcodes",
        i2c_hid::test_all_hid_commands_have_unique_opcodes,
    ));
    suite.add(TestCase::new("hid_command_opcode_range", i2c_hid::test_hid_command_opcode_range));
    suite.add(TestCase::new("usage_pages_are_distinct", i2c_hid::test_usage_pages_are_distinct));
    suite.add(TestCase::new("hid_register_sequence", i2c_hid::test_hid_register_sequence));

    // Input manager tests (10)
    suite.add(TestCase::new(
        "input_source_enum_values",
        input_manager::test_input_source_enum_values,
    ));
    suite.add(TestCase::new("input_source_not_equal", input_manager::test_input_source_not_equal));
    suite.add(TestCase::new("input_source_clone", input_manager::test_input_source_clone));
    suite.add(TestCase::new("input_source_copy", input_manager::test_input_source_copy));
    suite.add(TestCase::new("input_source_debug", input_manager::test_input_source_debug));
    suite.add(TestCase::new(
        "input_manager_struct_creation",
        input_manager::test_input_manager_struct_creation,
    ));
    suite.add(TestCase::new(
        "input_manager_source_returns_valid_source",
        input_manager::test_input_manager_source_returns_valid_source,
    ));
    suite.add(TestCase::new(
        "input_source_all_variants",
        input_manager::test_input_source_all_variants,
    ));
    suite.add(TestCase::new(
        "input_source_pattern_matching",
        input_manager::test_input_source_pattern_matching,
    ));
    suite.add(TestCase::new(
        "input_source_usb_pattern",
        input_manager::test_input_source_usb_pattern,
    ));
    suite.add(TestCase::new(
        "input_source_i2c_pattern",
        input_manager::test_input_source_i2c_pattern,
    ));

    // Keyboard tests (35)
    suite.add(TestCase::new("key_event_up_code", keyboard::test_key_event_up_code));
    suite.add(TestCase::new("key_event_down_code", keyboard::test_key_event_down_code));
    suite.add(TestCase::new("key_event_left_code", keyboard::test_key_event_left_code));
    suite.add(TestCase::new("key_event_right_code", keyboard::test_key_event_right_code));
    suite.add(TestCase::new("key_event_home_code", keyboard::test_key_event_home_code));
    suite.add(TestCase::new("key_event_end_code", keyboard::test_key_event_end_code));
    suite.add(TestCase::new("key_event_page_up_code", keyboard::test_key_event_page_up_code));
    suite.add(TestCase::new("key_event_page_down_code", keyboard::test_key_event_page_down_code));
    suite.add(TestCase::new("key_event_insert_code", keyboard::test_key_event_insert_code));
    suite.add(TestCase::new("key_event_delete_code", keyboard::test_key_event_delete_code));
    suite.add(TestCase::new("key_event_escape_code", keyboard::test_key_event_escape_code));
    suite.add(TestCase::new("key_event_backspace_code", keyboard::test_key_event_backspace_code));
    suite.add(TestCase::new("key_event_enter_code", keyboard::test_key_event_enter_code));
    suite.add(TestCase::new("key_event_f1_to_f12_codes", keyboard::test_key_event_f1_to_f12_codes));
    suite.add(TestCase::new(
        "key_event_from_code_arrows",
        keyboard::test_key_event_from_code_arrows,
    ));
    suite.add(TestCase::new(
        "key_event_from_code_navigation",
        keyboard::test_key_event_from_code_navigation,
    ));
    suite.add(TestCase::new(
        "key_event_from_code_special",
        keyboard::test_key_event_from_code_special,
    ));
    suite.add(TestCase::new(
        "key_event_from_code_function_keys",
        keyboard::test_key_event_from_code_function_keys,
    ));
    suite.add(TestCase::new(
        "key_event_from_code_invalid_zero",
        keyboard::test_key_event_from_code_invalid_zero,
    ));
    suite.add(TestCase::new(
        "key_event_from_code_invalid_high",
        keyboard::test_key_event_from_code_invalid_high,
    ));
    suite.add(TestCase::new("key_event_name_arrows", keyboard::test_key_event_name_arrows));
    suite.add(TestCase::new("key_event_name_navigation", keyboard::test_key_event_name_navigation));
    suite.add(TestCase::new("key_event_name_special", keyboard::test_key_event_name_special));
    suite.add(TestCase::new(
        "key_event_name_function_keys",
        keyboard::test_key_event_name_function_keys,
    ));
    suite.add(TestCase::new("key_event_is_arrow_true", keyboard::test_key_event_is_arrow_true));
    suite.add(TestCase::new("key_event_is_arrow_false", keyboard::test_key_event_is_arrow_false));
    suite.add(TestCase::new(
        "key_event_is_navigation_true",
        keyboard::test_key_event_is_navigation_true,
    ));
    suite.add(TestCase::new(
        "key_event_is_navigation_false",
        keyboard::test_key_event_is_navigation_false,
    ));
    suite.add(TestCase::new(
        "key_event_is_function_key_true",
        keyboard::test_key_event_is_function_key_true,
    ));
    suite.add(TestCase::new(
        "key_event_is_function_key_false",
        keyboard::test_key_event_is_function_key_false,
    ));
    suite.add(TestCase::new("key_event_roundtrip_all", keyboard::test_key_event_roundtrip_all));
    suite.add(TestCase::new("key_event_clone", keyboard::test_key_event_clone));
    suite.add(TestCase::new("key_event_copy", keyboard::test_key_event_copy));
    suite.add(TestCase::new("key_event_equality", keyboard::test_key_event_equality));
    suite.add(TestCase::new("key_event_debug", keyboard::test_key_event_debug));
    suite.add(TestCase::new("key_event_unique_codes", keyboard::test_key_event_unique_codes));
    suite.add(TestCase::new("key_event_code_range", keyboard::test_key_event_code_range));

    // Mouse tests (33)
    suite.add(TestCase::new("mouse_default_position", mouse::test_mouse_default_position));
    suite.add(TestCase::new("mouse_set_position", mouse::test_mouse_set_position));
    suite.add(TestCase::new("mouse_default_buttons", mouse::test_mouse_default_buttons));
    suite.add(TestCase::new(
        "mouse_left_button_not_pressed",
        mouse::test_mouse_left_button_not_pressed,
    ));
    suite.add(TestCase::new("mouse_left_button_pressed", mouse::test_mouse_left_button_pressed));
    suite.add(TestCase::new(
        "mouse_right_button_not_pressed",
        mouse::test_mouse_right_button_not_pressed,
    ));
    suite.add(TestCase::new("mouse_right_button_pressed", mouse::test_mouse_right_button_pressed));
    suite.add(TestCase::new(
        "mouse_middle_button_not_pressed",
        mouse::test_mouse_middle_button_not_pressed,
    ));
    suite
        .add(TestCase::new("mouse_middle_button_pressed", mouse::test_mouse_middle_button_pressed));
    suite.add(TestCase::new("mouse_all_buttons_pressed", mouse::test_mouse_all_buttons_pressed));
    suite.add(TestCase::new("mouse_buttons_bitmask", mouse::test_mouse_buttons_bitmask));
    suite.add(TestCase::new("mouse_set_screen_bounds", mouse::test_mouse_set_screen_bounds));
    suite.add(TestCase::new("mouse_screen_bounds_center", mouse::test_mouse_screen_bounds_center));
    suite.add(TestCase::new(
        "mouse_not_available_by_default",
        mouse::test_mouse_not_available_by_default,
    ));
    suite.add(TestCase::new("mouse_available", mouse::test_mouse_available));
    suite.add(TestCase::new(
        "mouse_scroll_wheel_not_available_by_default",
        mouse::test_mouse_scroll_wheel_not_available_by_default,
    ));
    suite.add(TestCase::new(
        "mouse_scroll_wheel_available",
        mouse::test_mouse_scroll_wheel_available,
    ));
    suite.add(TestCase::new(
        "mouse_scroll_delta_zero_default",
        mouse::test_mouse_scroll_delta_zero_default,
    ));
    suite
        .add(TestCase::new("mouse_scroll_delta_positive", mouse::test_mouse_scroll_delta_positive));
    suite
        .add(TestCase::new("mouse_scroll_delta_negative", mouse::test_mouse_scroll_delta_negative));
    suite.add(TestCase::new(
        "mouse_take_scroll_delta_clears",
        mouse::test_mouse_take_scroll_delta_clears,
    ));
    suite.add(TestCase::new(
        "mouse_take_scroll_delta_zero",
        mouse::test_mouse_take_scroll_delta_zero,
    ));
    suite.add(TestCase::new(
        "mouse_take_scroll_delta_multiple",
        mouse::test_mouse_take_scroll_delta_multiple,
    ));
    suite.add(TestCase::new("mouse_packet_index_default", mouse::test_mouse_packet_index_default));
    suite.add(TestCase::new("mouse_packet_bytes_default", mouse::test_mouse_packet_bytes_default));
    suite.add(TestCase::new(
        "mouse_position_boundary_left",
        mouse::test_mouse_position_boundary_left,
    ));
    suite
        .add(TestCase::new("mouse_position_boundary_top", mouse::test_mouse_position_boundary_top));
    suite.add(TestCase::new("mouse_position_negative", mouse::test_mouse_position_negative));
    suite.add(TestCase::new("mouse_large_position", mouse::test_mouse_large_position));
    suite.add(TestCase::new("mouse_screen_bounds_large", mouse::test_mouse_screen_bounds_large));
    suite.add(TestCase::new("mouse_screen_bounds_small", mouse::test_mouse_screen_bounds_small));
    suite
        .add(TestCase::new("mouse_button_bitmask_values", mouse::test_mouse_button_bitmask_values));
    suite.add(TestCase::new("mouse_atomic_ordering", mouse::test_mouse_atomic_ordering));
    suite.add(TestCase::new(
        "mouse_independent_button_states",
        mouse::test_mouse_independent_button_states,
    ));

    // Touchpad tests (51)
    suite.add(TestCase::new("touch_point_default", touchpad::test_touch_point_default));
    suite.add(TestCase::new("touch_point_area", touchpad::test_touch_point_area));
    suite.add(TestCase::new("touch_point_area_zero", touchpad::test_touch_point_area_zero));
    suite.add(TestCase::new(
        "touch_point_is_palm_by_area",
        touchpad::test_touch_point_is_palm_by_area,
    ));
    suite.add(TestCase::new(
        "touch_point_is_palm_by_pressure",
        touchpad::test_touch_point_is_palm_by_pressure,
    ));
    suite.add(TestCase::new(
        "touch_point_is_palm_by_left_edge",
        touchpad::test_touch_point_is_palm_by_left_edge,
    ));
    suite.add(TestCase::new(
        "touch_point_is_palm_by_right_edge",
        touchpad::test_touch_point_is_palm_by_right_edge,
    ));
    suite.add(TestCase::new(
        "touch_point_is_palm_by_top_edge",
        touchpad::test_touch_point_is_palm_by_top_edge,
    ));
    suite.add(TestCase::new(
        "touch_point_is_palm_by_bottom_edge",
        touchpad::test_touch_point_is_palm_by_bottom_edge,
    ));
    suite.add(TestCase::new("touch_point_not_palm", touchpad::test_touch_point_not_palm));
    suite.add(TestCase::new("gesture_default", touchpad::test_gesture_default));
    suite.add(TestCase::new("gesture_variants", touchpad::test_gesture_variants));
    suite.add(TestCase::new("gesture_two_finger_scroll", touchpad::test_gesture_two_finger_scroll));
    suite.add(TestCase::new("gesture_pinch_zoom", touchpad::test_gesture_pinch_zoom));
    suite.add(TestCase::new(
        "gesture_three_finger_swipes",
        touchpad::test_gesture_three_finger_swipes,
    ));
    suite.add(TestCase::new(
        "gesture_four_finger_swipes",
        touchpad::test_gesture_four_finger_swipes,
    ));
    suite.add(TestCase::new("touchpad_state_default", touchpad::test_touchpad_state_default));
    suite.add(TestCase::new("tracked_contact_default", touchpad::test_tracked_contact_default));
    suite.add(TestCase::new("constants_max_contacts", touchpad::test_constants_max_contacts));
    suite.add(TestCase::new("constants_palm_detection", touchpad::test_constants_palm_detection));
    suite.add(TestCase::new("constants_tap_timeouts", touchpad::test_constants_tap_timeouts));
    suite.add(TestCase::new(
        "constants_gesture_thresholds",
        touchpad::test_constants_gesture_thresholds,
    ));
    suite.add(TestCase::new("is_tap_event_short", touchpad::test_is_tap_event_short));
    suite.add(TestCase::new("is_tap_event_too_long", touchpad::test_is_tap_event_too_long));
    suite.add(TestCase::new("is_double_tap_quick", touchpad::test_is_double_tap_quick));
    suite.add(TestCase::new("is_double_tap_too_slow", touchpad::test_is_double_tap_too_slow));
    suite.add(TestCase::new("tap_timing_config", touchpad::test_tap_timing_config));
    suite.add(TestCase::new(
        "detect_two_finger_gesture_no_contacts",
        touchpad::test_detect_two_finger_gesture_no_contacts,
    ));
    suite.add(TestCase::new(
        "detect_two_finger_gesture_one_contact",
        touchpad::test_detect_two_finger_gesture_one_contact,
    ));
    suite.add(TestCase::new(
        "detect_three_finger_gesture_no_contacts",
        touchpad::test_detect_three_finger_gesture_no_contacts,
    ));
    suite.add(TestCase::new(
        "detect_four_finger_gesture_no_contacts",
        touchpad::test_detect_four_finger_gesture_no_contacts,
    ));
    suite.add(TestCase::new(
        "apply_acceleration_small_delta",
        touchpad::test_apply_acceleration_small_delta,
    ));
    suite.add(TestCase::new(
        "apply_acceleration_medium_delta",
        touchpad::test_apply_acceleration_medium_delta,
    ));
    suite.add(TestCase::new(
        "apply_acceleration_large_delta",
        touchpad::test_apply_acceleration_large_delta,
    ));
    suite.add(TestCase::new(
        "apply_acceleration_very_large_delta",
        touchpad::test_apply_acceleration_very_large_delta,
    ));
    suite.add(TestCase::new(
        "apply_acceleration_negative",
        touchpad::test_apply_acceleration_negative,
    ));
    suite.add(TestCase::new("distance_zero", touchpad::test_distance_zero));
    suite.add(TestCase::new("distance_horizontal", touchpad::test_distance_horizontal));
    suite.add(TestCase::new("distance_vertical", touchpad::test_distance_vertical));
    suite.add(TestCase::new("distance_diagonal", touchpad::test_distance_diagonal));
    suite.add(TestCase::new("isqrt_zero", touchpad::test_isqrt_zero));
    suite.add(TestCase::new("isqrt_one", touchpad::test_isqrt_one));
    suite.add(TestCase::new("isqrt_four", touchpad::test_isqrt_four));
    suite.add(TestCase::new("isqrt_nine", touchpad::test_isqrt_nine));
    suite.add(TestCase::new("isqrt_sixteen", touchpad::test_isqrt_sixteen));
    suite.add(TestCase::new("isqrt_large", touchpad::test_isqrt_large));
    suite.add(TestCase::new("isqrt_non_perfect", touchpad::test_isqrt_non_perfect));
    suite.add(TestCase::new(
        "touchpad_state_contacts_array_size",
        touchpad::test_touchpad_state_contacts_array_size,
    ));
    suite.add(TestCase::new("touch_point_clone", touchpad::test_touch_point_clone));
    suite.add(TestCase::new("tracked_contact_clone", touchpad::test_tracked_contact_clone));
    suite.add(TestCase::new("gesture_clone", touchpad::test_gesture_clone));
    suite.add(TestCase::new("touchpad_state_clone", touchpad::test_touchpad_state_clone));

    // USB HID tests (28)
    suite.add(TestCase::new("hid_to_ascii_letters", usb_hid::test_hid_to_ascii_letters));
    suite.add(TestCase::new(
        "hid_to_ascii_shifted_letters",
        usb_hid::test_hid_to_ascii_shifted_letters,
    ));
    suite.add(TestCase::new("hid_to_ascii_numbers", usb_hid::test_hid_to_ascii_numbers));
    suite.add(TestCase::new(
        "hid_to_ascii_shifted_numbers",
        usb_hid::test_hid_to_ascii_shifted_numbers,
    ));
    suite.add(TestCase::new("hid_to_ascii_special_keys", usb_hid::test_hid_to_ascii_special_keys));
    suite.add(TestCase::new("hid_to_ascii_punctuation", usb_hid::test_hid_to_ascii_punctuation));
    suite.add(TestCase::new(
        "hid_to_ascii_shifted_punctuation",
        usb_hid::test_hid_to_ascii_shifted_punctuation,
    ));
    suite.add(TestCase::new("hid_to_ascii_invalid_code", usb_hid::test_hid_to_ascii_invalid_code));
    suite.add(TestCase::new("hid_to_ascii_out_of_range", usb_hid::test_hid_to_ascii_out_of_range));
    suite.add(TestCase::new(
        "hid_to_ascii_forward_delete",
        usb_hid::test_hid_to_ascii_forward_delete,
    ));
    suite.add(TestCase::new("trb_type_constants", usb_hid::test_trb_type_constants));
    suite.add(TestCase::new("trb_flag_constants", usb_hid::test_trb_flag_constants));
    suite.add(TestCase::new("usb_request_constants", usb_hid::test_usb_request_constants));
    suite.add(TestCase::new(
        "usb_descriptor_type_constants",
        usb_hid::test_usb_descriptor_type_constants,
    ));
    suite.add(TestCase::new("usb_class_hid", usb_hid::test_usb_class_hid));
    suite.add(TestCase::new("ep_info_is_interrupt", usb_hid::test_ep_info_is_interrupt));
    suite.add(TestCase::new("ep_info_structure", usb_hid::test_ep_info_structure));
    suite.add(TestCase::new("usb_state_defaults", usb_hid::test_usb_state_defaults));
    suite.add(TestCase::new("usb_state_initialization", usb_hid::test_usb_state_initialization));
    suite.add(TestCase::new("usb_mouse_position", usb_hid::test_usb_mouse_position));
    suite.add(TestCase::new("usb_mouse_buttons", usb_hid::test_usb_mouse_buttons));
    suite.add(TestCase::new("usb_screen_bounds", usb_hid::test_usb_screen_bounds));
    suite.add(TestCase::new("hid_modifier_left_shift", usb_hid::test_hid_modifier_left_shift));
    suite.add(TestCase::new("hid_modifier_right_shift", usb_hid::test_hid_modifier_right_shift));
    suite.add(TestCase::new("hid_modifier_no_shift", usb_hid::test_hid_modifier_no_shift));
    suite.add(TestCase::new("endpoint_direction", usb_hid::test_endpoint_direction));
    suite.add(TestCase::new("endpoint_number", usb_hid::test_endpoint_number));

    suite.run()
}
