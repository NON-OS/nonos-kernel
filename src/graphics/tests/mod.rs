pub mod animation;
pub mod colors;
pub mod components;
pub mod context_menu;
pub mod design_system;
pub mod dialogs;
pub mod ecosystem;
pub mod file_manager;
pub mod font;
pub mod image;
pub mod settings;
pub mod themes;
pub mod window_state;

use crate::test::framework::{TestCase, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("graphics");

    // Animation tests (45)
    suite.add_test(TestCase::new("easing_values", animation::test_easing_values, "animation"));
    suite.add_test(TestCase::new("easing_inequality", animation::test_easing_inequality, "animation"));
    suite.add_test(TestCase::new("apply_easing_linear", animation::test_apply_easing_linear, "animation"));
    suite.add_test(TestCase::new("apply_easing_clamps_input", animation::test_apply_easing_clamps_input, "animation"));
    suite.add_test(TestCase::new("apply_easing_ease_in", animation::test_apply_easing_ease_in, "animation"));
    suite.add_test(TestCase::new("apply_easing_ease_out", animation::test_apply_easing_ease_out, "animation"));
    suite.add_test(TestCase::new("apply_easing_ease_in_out", animation::test_apply_easing_ease_in_out, "animation"));
    suite.add_test(TestCase::new("apply_easing_spring", animation::test_apply_easing_spring, "animation"));
    suite.add_test(TestCase::new("interpolate", animation::test_interpolate, "animation"));
    suite.add_test(TestCase::new("interpolate_negative", animation::test_interpolate_negative, "animation"));
    suite.add_test(TestCase::new("interpolate_u32", animation::test_interpolate_u32, "animation"));
    suite.add_test(TestCase::new("interpolate_u32_boundary", animation::test_interpolate_u32_boundary, "animation"));
    suite.add_test(TestCase::new("interpolate_color", animation::test_interpolate_color, "animation"));
    suite.add_test(TestCase::new("interpolate_color_midpoint", animation::test_interpolate_color_midpoint, "animation"));
    suite.add_test(TestCase::new("interpolate_color_alpha", animation::test_interpolate_color_alpha, "animation"));
    suite.add_test(TestCase::new("animation_status_values", animation::test_animation_status_values, "animation"));
    suite.add_test(TestCase::new("animation_status_inequality", animation::test_animation_status_inequality, "animation"));
    suite.add_test(TestCase::new("animation_new", animation::test_animation_new, "animation"));
    suite.add_test(TestCase::new("animation_with_delay", animation::test_animation_with_delay, "animation"));
    suite.add_test(TestCase::new("animation_start", animation::test_animation_start, "animation"));
    suite.add_test(TestCase::new("animation_progress_idle", animation::test_animation_progress_idle, "animation"));
    suite.add_test(TestCase::new("animation_progress_completed", animation::test_animation_progress_completed, "animation"));
    suite.add_test(TestCase::new("animation_progress_running", animation::test_animation_progress_running, "animation"));
    suite.add_test(TestCase::new("animation_progress_with_delay", animation::test_animation_progress_with_delay, "animation"));
    suite.add_test(TestCase::new("animation_current_value", animation::test_animation_current_value, "animation"));
    suite.add_test(TestCase::new("animation_is_complete", animation::test_animation_is_complete, "animation"));
    suite.add_test(TestCase::new("animation_complete", animation::test_animation_complete, "animation"));
    suite.add_test(TestCase::new("animation_reset", animation::test_animation_reset, "animation"));
    suite.add_test(TestCase::new("animation_default", animation::test_animation_default, "animation"));
    suite.add_test(TestCase::new("animation_copy", animation::test_animation_copy, "animation"));
    suite.add_test(TestCase::new("transition_fade_in", animation::test_transition_fade_in, "animation"));
    suite.add_test(TestCase::new("transition_fade_out", animation::test_transition_fade_out, "animation"));
    suite.add_test(TestCase::new("transition_slide_in_left", animation::test_transition_slide_in_left, "animation"));
    suite.add_test(TestCase::new("transition_slide_in_right", animation::test_transition_slide_in_right, "animation"));
    suite.add_test(TestCase::new("transition_slide_in_up", animation::test_transition_slide_in_up, "animation"));
    suite.add_test(TestCase::new("transition_slide_in_down", animation::test_transition_slide_in_down, "animation"));
    suite.add_test(TestCase::new("transition_scale_in", animation::test_transition_scale_in, "animation"));
    suite.add_test(TestCase::new("transition_scale_out", animation::test_transition_scale_out, "animation"));
    suite.add_test(TestCase::new("transition_hover_grow", animation::test_transition_hover_grow, "animation"));
    suite.add_test(TestCase::new("transition_hover_shrink", animation::test_transition_hover_shrink, "animation"));
    suite.add_test(TestCase::new("transition_press", animation::test_transition_press, "animation"));
    suite.add_test(TestCase::new("transition_release", animation::test_transition_release, "animation"));
    suite.add_test(TestCase::new("transition_pulse_glow", animation::test_transition_pulse_glow, "animation"));
    suite.add_test(TestCase::new("transition_spinner_rotation", animation::test_transition_spinner_rotation, "animation"));
    suite.add_test(TestCase::new("duration_constants", animation::test_duration_constants, "animation"));
    suite.add_test(TestCase::new("timing_constants", animation::test_timing_constants, "animation"));
    suite.add_test(TestCase::new("timing_ms_to_frames", animation::test_timing_ms_to_frames, "animation"));
    suite.add_test(TestCase::new("timing_frames_to_ms", animation::test_timing_frames_to_ms, "animation"));
    suite.add_test(TestCase::new("timing_should_update_animation", animation::test_timing_should_update_animation, "animation"));

    // Colors tests (19)
    suite.add_test(TestCase::new("brand_accent_colors", colors::test_brand_accent_colors, "colors"));
    suite.add_test(TestCase::new("brand_secondary_colors", colors::test_brand_secondary_colors, "colors"));
    suite.add_test(TestCase::new("background_colors", colors::test_background_colors, "colors"));
    suite.add_test(TestCase::new("panel_colors", colors::test_panel_colors, "colors"));
    suite.add_test(TestCase::new("text_colors", colors::test_text_colors, "colors"));
    suite.add_test(TestCase::new("terminal_colors", colors::test_terminal_colors, "colors"));
    suite.add_test(TestCase::new("semantic_colors", colors::test_semantic_colors, "colors"));
    suite.add_test(TestCase::new("ui_state_colors", colors::test_ui_state_colors, "colors"));
    suite.add_test(TestCase::new("cursor_colors", colors::test_cursor_colors, "colors"));
    suite.add_test(TestCase::new("grid_colors", colors::test_grid_colors, "colors"));
    suite.add_test(TestCase::new("legacy_aliases", colors::test_legacy_aliases, "colors"));
    suite.add_test(TestCase::new("menu_aliases", colors::test_menu_aliases, "colors"));
    suite.add_test(TestCase::new("title_aliases", colors::test_title_aliases, "colors"));
    suite.add_test(TestCase::new("color_format_argb", colors::test_color_format_argb, "colors"));
    suite.add_test(TestCase::new("glow_colors_have_alpha", colors::test_glow_colors_have_alpha, "colors"));
    suite.add_test(TestCase::new("opaque_colors_have_full_alpha", colors::test_opaque_colors_have_full_alpha, "colors"));
    suite.add_test(TestCase::new("semantic_color_consistency", colors::test_semantic_color_consistency, "colors"));
    suite.add_test(TestCase::new("black_white_contrast", colors::test_black_white_contrast, "colors"));
    suite.add_test(TestCase::new("background_is_dark", colors::test_background_is_dark, "colors"));

    // Components tests (11)
    suite.add_test(TestCase::new("input_state_default", components::test_input_state_default, "components"));
    suite.add_test(TestCase::new("input_state_focused", components::test_input_state_focused, "components"));
    suite.add_test(TestCase::new("input_state_error", components::test_input_state_error, "components"));
    suite.add_test(TestCase::new("input_hit_test_inside", components::test_input_hit_test_inside, "components"));
    suite.add_test(TestCase::new("input_hit_test_outside", components::test_input_hit_test_outside, "components"));
    suite.add_test(TestCase::new("input_hit_test_boundary", components::test_input_hit_test_boundary, "components"));
    suite.add_test(TestCase::new("cursor_pos_from_click_start", components::test_cursor_pos_from_click_start, "components"));
    suite.add_test(TestCase::new("cursor_pos_from_click_before_text", components::test_cursor_pos_from_click_before_text, "components"));
    suite.add_test(TestCase::new("cursor_pos_from_click_middle", components::test_cursor_pos_from_click_middle, "components"));
    suite.add_test(TestCase::new("cursor_pos_from_click_past_end", components::test_cursor_pos_from_click_past_end, "components"));
    suite.add_test(TestCase::new("cursor_pos_from_click_exact_char", components::test_cursor_pos_from_click_exact_char, "components"));
    suite.add_test(TestCase::new("cursor_pos_zero_length", components::test_cursor_pos_zero_length, "components"));
    suite.add_test(TestCase::new("input_state_combinations", components::test_input_state_combinations, "components"));

    // Context menu tests (18)
    suite.add_test(TestCase::new("menu_item_type_values", context_menu::test_menu_item_type_values, "context_menu"));
    suite.add_test(TestCase::new("menu_item_type_inequality", context_menu::test_menu_item_type_inequality, "context_menu"));
    suite.add_test(TestCase::new("menu_item_action", context_menu::test_menu_item_action, "context_menu"));
    suite.add_test(TestCase::new("menu_item_separator", context_menu::test_menu_item_separator, "context_menu"));
    suite.add_test(TestCase::new("menu_item_disabled", context_menu::test_menu_item_disabled, "context_menu"));
    suite.add_test(TestCase::new("context_menu_type_values", context_menu::test_context_menu_type_values, "context_menu"));
    suite.add_test(TestCase::new("context_menu_type_equality", context_menu::test_context_menu_type_equality, "context_menu"));
    suite.add_test(TestCase::new("context_menu_type_inequality", context_menu::test_context_menu_type_inequality, "context_menu"));
    suite.add_test(TestCase::new("context_menu_type_copy", context_menu::test_context_menu_type_copy, "context_menu"));
    suite.add_test(TestCase::new("menu_item_type_copy", context_menu::test_menu_item_type_copy, "context_menu"));
    suite.add_test(TestCase::new("menu_item_copy", context_menu::test_menu_item_copy, "context_menu"));
    suite.add_test(TestCase::new("menu_item_const_action", context_menu::test_menu_item_const_action, "context_menu"));
    suite.add_test(TestCase::new("menu_item_const_separator", context_menu::test_menu_item_const_separator, "context_menu"));
    suite.add_test(TestCase::new("menu_item_const_disabled", context_menu::test_menu_item_const_disabled, "context_menu"));
    suite.add_test(TestCase::new("menu_items_array", context_menu::test_menu_items_array, "context_menu"));
    suite.add_test(TestCase::new("action_ids_unique", context_menu::test_action_ids_unique, "context_menu"));
    suite.add_test(TestCase::new("menu_item_empty_label", context_menu::test_menu_item_empty_label, "context_menu"));
    suite.add_test(TestCase::new("menu_item_long_label", context_menu::test_menu_item_long_label, "context_menu"));

    // Design system tests (23)
    suite.add_test(TestCase::new("border_radius_values", design_system::test_border_radius_values, "design_system"));
    suite.add_test(TestCase::new("border_component_radius", design_system::test_border_component_radius, "design_system"));
    suite.add_test(TestCase::new("border_width_values", design_system::test_border_width_values, "design_system"));
    suite.add_test(TestCase::new("clamp_radius_no_clamp", design_system::test_clamp_radius_no_clamp, "design_system"));
    suite.add_test(TestCase::new("clamp_radius_clamps_to_width", design_system::test_clamp_radius_clamps_to_width, "design_system"));
    suite.add_test(TestCase::new("clamp_radius_clamps_to_height", design_system::test_clamp_radius_clamps_to_height, "design_system"));
    suite.add_test(TestCase::new("clamp_radius_at_limit", design_system::test_clamp_radius_at_limit, "design_system"));
    suite.add_test(TestCase::new("is_pill_true", design_system::test_is_pill_true, "design_system"));
    suite.add_test(TestCase::new("is_pill_false", design_system::test_is_pill_false, "design_system"));
    suite.add_test(TestCase::new("is_pill_boundary", design_system::test_is_pill_boundary, "design_system"));
    suite.add_test(TestCase::new("spacing_unit", design_system::test_spacing_unit, "design_system"));
    suite.add_test(TestCase::new("spacing_scale", design_system::test_spacing_scale, "design_system"));
    suite.add_test(TestCase::new("spacing_scale_multiples", design_system::test_spacing_scale_multiples, "design_system"));
    suite.add_test(TestCase::new("semantic_accent_color", design_system::test_semantic_accent_color, "design_system"));
    suite.add_test(TestCase::new("semantic_success_color", design_system::test_semantic_success_color, "design_system"));
    suite.add_test(TestCase::new("semantic_warning_color", design_system::test_semantic_warning_color, "design_system"));
    suite.add_test(TestCase::new("semantic_error_color", design_system::test_semantic_error_color, "design_system"));
    suite.add_test(TestCase::new("semantic_info_color", design_system::test_semantic_info_color, "design_system"));
    suite.add_test(TestCase::new("semantic_other_colors", design_system::test_semantic_other_colors, "design_system"));
    suite.add_test(TestCase::new("border_radius_hierarchy", design_system::test_border_radius_hierarchy, "design_system"));
    suite.add_test(TestCase::new("border_width_hierarchy", design_system::test_border_width_hierarchy, "design_system"));
    suite.add_test(TestCase::new("spacing_hierarchy", design_system::test_spacing_hierarchy, "design_system"));
    suite.add_test(TestCase::new("semantic_colors_opaque", design_system::test_semantic_colors_opaque, "design_system"));

    // Dialogs tests (20)
    suite.add_test(TestCase::new("max_message_len", dialogs::test_max_message_len, "dialogs"));
    suite.add_test(TestCase::new("max_title_len", dialogs::test_max_title_len, "dialogs"));
    suite.add_test(TestCase::new("max_input_len", dialogs::test_max_input_len, "dialogs"));
    suite.add_test(TestCase::new("dialog_type_values", dialogs::test_dialog_type_values, "dialogs"));
    suite.add_test(TestCase::new("dialog_type_unique", dialogs::test_dialog_type_unique, "dialogs"));
    suite.add_test(TestCase::new("result_values", dialogs::test_result_values, "dialogs"));
    suite.add_test(TestCase::new("result_values_unique", dialogs::test_result_values_unique, "dialogs"));
    suite.add_test(TestCase::new("input_callback_values", dialogs::test_input_callback_values, "dialogs"));
    suite.add_test(TestCase::new("input_callback_unique", dialogs::test_input_callback_unique, "dialogs"));
    suite.add_test(TestCase::new("show_and_close_dialog", dialogs::test_show_and_close_dialog, "dialogs"));
    suite.add_test(TestCase::new("dialog_types", dialogs::test_dialog_types, "dialogs"));
    suite.add_test(TestCase::new("show_input_dialog", dialogs::test_show_input_dialog, "dialogs"));
    suite.add_test(TestCase::new("input_push_char", dialogs::test_input_push_char, "dialogs"));
    suite.add_test(TestCase::new("input_pop_char", dialogs::test_input_pop_char, "dialogs"));
    suite.add_test(TestCase::new("input_pop_char_empty", dialogs::test_input_pop_char_empty, "dialogs"));
    suite.add_test(TestCase::new("close_resets_input", dialogs::test_close_resets_input, "dialogs"));
    suite.add_test(TestCase::new("input_max_length", dialogs::test_input_max_length, "dialogs"));
    suite.add_test(TestCase::new("dialog_truncates_long_title", dialogs::test_dialog_truncates_long_title, "dialogs"));
    suite.add_test(TestCase::new("dialog_truncates_long_message", dialogs::test_dialog_truncates_long_message, "dialogs"));
    suite.add_test(TestCase::new("dialog_empty_title", dialogs::test_dialog_empty_title, "dialogs"));
    suite.add_test(TestCase::new("dialog_empty_message", dialogs::test_dialog_empty_message, "dialogs"));

    // Ecosystem tests (17)
    suite.add_test(TestCase::new("ecosystem_tab_values", ecosystem::test_ecosystem_tab_values, "ecosystem"));
    suite.add_test(TestCase::new("ecosystem_tab_from_u8", ecosystem::test_ecosystem_tab_from_u8, "ecosystem"));
    suite.add_test(TestCase::new("ecosystem_tab_from_u8_invalid", ecosystem::test_ecosystem_tab_from_u8_invalid, "ecosystem"));
    suite.add_test(TestCase::new("ecosystem_tab_label", ecosystem::test_ecosystem_tab_label, "ecosystem"));
    suite.add_test(TestCase::new("ecosystem_tab_count", ecosystem::test_ecosystem_tab_count, "ecosystem"));
    suite.add_test(TestCase::new("ecosystem_tab_equality", ecosystem::test_ecosystem_tab_equality, "ecosystem"));
    suite.add_test(TestCase::new("ecosystem_tab_copy", ecosystem::test_ecosystem_tab_copy, "ecosystem"));
    suite.add_test(TestCase::new("ecosystem_tab_roundtrip", ecosystem::test_ecosystem_tab_roundtrip, "ecosystem"));
    suite.add_test(TestCase::new("tab_labels_not_empty", ecosystem::test_tab_labels_not_empty, "ecosystem"));
    suite.add_test(TestCase::new("ecosystem_tab_default", ecosystem::test_ecosystem_tab_default, "ecosystem"));
    suite.add_test(TestCase::new("get_set_active_tab", ecosystem::test_get_set_active_tab, "ecosystem"));
    suite.add_test(TestCase::new("set_all_tabs", ecosystem::test_set_all_tabs, "ecosystem"));
    suite.add_test(TestCase::new("input_focused_query", ecosystem::test_input_focused_query, "ecosystem"));
    suite.add_test(TestCase::new("tab_constants", ecosystem::test_tab_constants, "ecosystem"));
    suite.add_test(TestCase::new("tab_colors", ecosystem::test_tab_colors, "ecosystem"));
    suite.add_test(TestCase::new("tab_layout_calculation", ecosystem::test_tab_layout_calculation, "ecosystem"));
    suite.add_test(TestCase::new("tab_layout_narrow_width", ecosystem::test_tab_layout_narrow_width, "ecosystem"));
    suite.add_test(TestCase::new("tab_layout_wide_width", ecosystem::test_tab_layout_wide_width, "ecosystem"));

    // File manager tests (3)
    suite.add_test(TestCase::new("module_exists", file_manager::test_module_exists, "file_manager"));
    suite.add_test(TestCase::new("basic_constants", file_manager::test_basic_constants, "file_manager"));
    suite.add_test(TestCase::new("basic_operations", file_manager::test_basic_operations, "file_manager"));

    // Font tests (17)
    suite.add_test(TestCase::new("char_dimensions", font::test_char_dimensions, "font"));
    suite.add_test(TestCase::new("char_bitmap_uppercase_letters", font::test_char_bitmap_uppercase_letters, "font"));
    suite.add_test(TestCase::new("char_bitmap_lowercase_letters", font::test_char_bitmap_lowercase_letters, "font"));
    suite.add_test(TestCase::new("char_bitmap_digits", font::test_char_bitmap_digits, "font"));
    suite.add_test(TestCase::new("char_bitmap_space", font::test_char_bitmap_space, "font"));
    suite.add_test(TestCase::new("char_bitmap_punctuation", font::test_char_bitmap_punctuation, "font"));
    suite.add_test(TestCase::new("char_bitmap_brackets", font::test_char_bitmap_brackets, "font"));
    suite.add_test(TestCase::new("char_bitmap_symbols", font::test_char_bitmap_symbols, "font"));
    suite.add_test(TestCase::new("char_bitmap_quotes", font::test_char_bitmap_quotes, "font"));
    suite.add_test(TestCase::new("char_bitmap_slashes", font::test_char_bitmap_slashes, "font"));
    suite.add_test(TestCase::new("char_bitmap_special", font::test_char_bitmap_special, "font"));
    suite.add_test(TestCase::new("char_bitmap_unknown", font::test_char_bitmap_unknown, "font"));
    suite.add_test(TestCase::new("char_bitmap_nonos_o", font::test_char_bitmap_nonos_o, "font"));
    suite.add_test(TestCase::new("different_chars_different_bitmaps", font::test_different_chars_different_bitmaps, "font"));
    suite.add_test(TestCase::new("case_sensitive_bitmaps", font::test_case_sensitive_bitmaps, "font"));
    suite.add_test(TestCase::new("bitmap_has_content", font::test_bitmap_has_content, "font"));
    suite.add_test(TestCase::new("bitmap_within_width", font::test_bitmap_within_width, "font"));
    suite.add_test(TestCase::new("all_printable_ascii", font::test_all_printable_ascii, "font"));

    // Image tests (14)
    suite.add_test(TestCase::new("decoded_image_new", image::test_decoded_image_new, "image"));
    suite.add_test(TestCase::new("decoded_image_empty", image::test_decoded_image_empty, "image"));
    suite.add_test(TestCase::new("decoded_image_get_pixel", image::test_decoded_image_get_pixel, "image"));
    suite.add_test(TestCase::new("decoded_image_get_pixel_out_of_bounds", image::test_decoded_image_get_pixel_out_of_bounds, "image"));
    suite.add_test(TestCase::new("decoded_image_get_pixel_boundary", image::test_decoded_image_get_pixel_boundary, "image"));
    suite.add_test(TestCase::new("decoded_image_dimensions", image::test_decoded_image_dimensions, "image"));
    suite.add_test(TestCase::new("decoded_image_pixel_count", image::test_decoded_image_pixel_count, "image"));
    suite.add_test(TestCase::new("decoded_image_clone", image::test_decoded_image_clone, "image"));
    suite.add_test(TestCase::new("decoded_image_pixel_layout", image::test_decoded_image_pixel_layout, "image"));
    suite.add_test(TestCase::new("decoded_image_large", image::test_decoded_image_large, "image"));
    suite.add_test(TestCase::new("decoded_image_single_pixel", image::test_decoded_image_single_pixel, "image"));
    suite.add_test(TestCase::new("decoded_image_row_major", image::test_decoded_image_row_major, "image"));
    suite.add_test(TestCase::new("decoded_image_transparent_pixels", image::test_decoded_image_transparent_pixels, "image"));

    // Settings tests (3)
    suite.add_test(TestCase::new("settings_module_exists", settings::test_settings_module_exists, "settings"));
    suite.add_test(TestCase::new("theme_values", settings::test_theme_values, "settings"));
    suite.add_test(TestCase::new("font_sizes", settings::test_font_sizes, "settings"));

    // Themes tests (21)
    suite.add_test(TestCase::new("theme_values", themes::test_theme_values, "themes"));
    suite.add_test(TestCase::new("theme_from_u8", themes::test_theme_from_u8, "themes"));
    suite.add_test(TestCase::new("theme_from_u8_invalid", themes::test_theme_from_u8_invalid, "themes"));
    suite.add_test(TestCase::new("theme_count", themes::test_theme_count, "themes"));
    suite.add_test(TestCase::new("theme_name", themes::test_theme_name, "themes"));
    suite.add_test(TestCase::new("theme_next", themes::test_theme_next, "themes"));
    suite.add_test(TestCase::new("theme_prev", themes::test_theme_prev, "themes"));
    suite.add_test(TestCase::new("theme_cycle_next_full", themes::test_theme_cycle_next_full, "themes"));
    suite.add_test(TestCase::new("theme_cycle_prev_full", themes::test_theme_cycle_prev_full, "themes"));
    suite.add_test(TestCase::new("color_scheme_nonos_dark", themes::test_color_scheme_nonos_dark, "themes"));
    suite.add_test(TestCase::new("color_scheme_solarized", themes::test_color_scheme_solarized, "themes"));
    suite.add_test(TestCase::new("color_scheme_deep_purple", themes::test_color_scheme_deep_purple, "themes"));
    suite.add_test(TestCase::new("color_scheme_ocean_blue", themes::test_color_scheme_ocean_blue, "themes"));
    suite.add_test(TestCase::new("color_scheme_forest_green", themes::test_color_scheme_forest_green, "themes"));
    suite.add_test(TestCase::new("all_themes_have_valid_colors", themes::test_all_themes_have_valid_colors, "themes"));
    suite.add_test(TestCase::new("theme_equality", themes::test_theme_equality, "themes"));
    suite.add_test(TestCase::new("theme_copy", themes::test_theme_copy, "themes"));
    suite.add_test(TestCase::new("color_scheme_copy", themes::test_color_scheme_copy, "themes"));
    suite.add_test(TestCase::new("theme_roundtrip", themes::test_theme_roundtrip, "themes"));

    // Window state tests (14)
    suite.add_test(TestCase::new("window_type_values", window_state::test_window_type_values, "window_state"));
    suite.add_test(TestCase::new("window_type_from_u32", window_state::test_window_type_from_u32, "window_state"));
    suite.add_test(TestCase::new("window_type_from_u32_invalid", window_state::test_window_type_from_u32_invalid, "window_state"));
    suite.add_test(TestCase::new("window_type_equality", window_state::test_window_type_equality, "window_state"));
    suite.add_test(TestCase::new("snap_zone_values", window_state::test_snap_zone_values, "window_state"));
    suite.add_test(TestCase::new("snap_zone_from_u8", window_state::test_snap_zone_from_u8, "window_state"));
    suite.add_test(TestCase::new("snap_zone_from_u8_invalid", window_state::test_snap_zone_from_u8_invalid, "window_state"));
    suite.add_test(TestCase::new("snap_zone_default", window_state::test_snap_zone_default, "window_state"));
    suite.add_test(TestCase::new("max_windows_constant", window_state::test_max_windows_constant, "window_state"));
    suite.add_test(TestCase::new("window_padding_constant", window_state::test_window_padding_constant, "window_state"));
    suite.add_test(TestCase::new("windows_array_length", window_state::test_windows_array_length, "window_state"));
    suite.add_test(TestCase::new("window_type_copy", window_state::test_window_type_copy, "window_state"));
    suite.add_test(TestCase::new("snap_zone_copy", window_state::test_snap_zone_copy, "window_state"));
    suite.add_test(TestCase::new("window_type_roundtrip", window_state::test_window_type_roundtrip, "window_state"));
    suite.add_test(TestCase::new("snap_zone_roundtrip", window_state::test_snap_zone_roundtrip, "window_state"));

    suite.run()
}
