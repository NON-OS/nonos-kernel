// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

mod alias;
mod buffer;
mod completion;
mod editor;
mod env;
mod expand;
mod history;
mod input;
mod pipeline;
mod script;
mod utils;

use crate::test::framework::{TestCase, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("shell");

    // Alias tests (32)
    suite.add(TestCase::new("max_aliases_constant", alias::test_max_aliases_constant));
    suite.add(TestCase::new("max_alias_name_constant", alias::test_max_alias_name_constant));
    suite.add(TestCase::new("max_alias_value_constant", alias::test_max_alias_value_constant));
    suite.add(TestCase::new("alias_empty", alias::test_alias_empty));
    suite.add(TestCase::new("alias_empty_name_array", alias::test_alias_empty_name_array));
    suite.add(TestCase::new("alias_empty_value_array", alias::test_alias_empty_value_array));
    suite.add(TestCase::new("alias_table_new", alias::test_alias_table_new));
    suite.add(TestCase::new("alias_table_set_single", alias::test_alias_table_set_single));
    suite.add(TestCase::new("alias_table_get_existing", alias::test_alias_table_get_existing));
    suite
        .add(TestCase::new("alias_table_get_nonexistent", alias::test_alias_table_get_nonexistent));
    suite.add(TestCase::new("alias_table_set_multiple", alias::test_alias_table_set_multiple));
    suite.add(TestCase::new(
        "alias_table_set_update_existing",
        alias::test_alias_table_set_update_existing,
    ));
    suite.add(TestCase::new("alias_table_unset_existing", alias::test_alias_table_unset_existing));
    suite.add(TestCase::new(
        "alias_table_unset_nonexistent",
        alias::test_alias_table_unset_nonexistent,
    ));
    suite.add(TestCase::new("alias_table_unset_middle", alias::test_alias_table_unset_middle));
    suite.add(TestCase::new("alias_table_expand_simple", alias::test_alias_table_expand_simple));
    suite.add(TestCase::new(
        "alias_table_expand_with_args",
        alias::test_alias_table_expand_with_args,
    ));
    suite.add(TestCase::new(
        "alias_table_expand_nonexistent",
        alias::test_alias_table_expand_nonexistent,
    ));
    suite.add(TestCase::new("alias_table_init_defaults", alias::test_alias_table_init_defaults));
    suite.add(TestCase::new("alias_table_secure_erase", alias::test_alias_table_secure_erase));
    suite.add(TestCase::new(
        "alias_table_secure_erase_clears_all",
        alias::test_alias_table_secure_erase_clears_all,
    ));
    suite.add(TestCase::new("alias_table_max_capacity", alias::test_alias_table_max_capacity));
    suite.add(TestCase::new("alias_table_over_capacity", alias::test_alias_table_over_capacity));
    suite.add(TestCase::new("alias_truncates_long_name", alias::test_alias_truncates_long_name));
    suite.add(TestCase::new("alias_truncates_long_value", alias::test_alias_truncates_long_value));
    suite.add(TestCase::new("alias_table_empty_name", alias::test_alias_table_empty_name));
    suite.add(TestCase::new("alias_table_empty_value", alias::test_alias_table_empty_value));
    suite.add(TestCase::new("alias_copy", alias::test_alias_copy));
    suite.add(TestCase::new("alias_clone", alias::test_alias_clone));
    suite.add(TestCase::new(
        "alias_table_expand_preserves_whitespace",
        alias::test_alias_table_expand_preserves_whitespace,
    ));
    suite.add(TestCase::new(
        "alias_table_get_after_unset_others",
        alias::test_alias_table_get_after_unset_others,
    ));
    suite.add(TestCase::new("alias_table_const_new", alias::test_alias_table_const_new));
    suite.add(TestCase::new("alias_const_empty", alias::test_alias_const_empty));

    // Buffer tests (34)
    suite.add(TestCase::new("buffer_new_empty", buffer::test_buffer_new_empty));
    suite.add(TestCase::new("buffer_from_string_empty", buffer::test_buffer_from_string_empty));
    suite.add(TestCase::new(
        "buffer_from_string_single_line",
        buffer::test_buffer_from_string_single_line,
    ));
    suite.add(TestCase::new(
        "buffer_from_string_multiple_lines",
        buffer::test_buffer_from_string_multiple_lines,
    ));
    suite.add(TestCase::new("buffer_from_file", buffer::test_buffer_from_file));
    suite.add(TestCase::new("buffer_filename_none", buffer::test_buffer_filename_none));
    suite.add(TestCase::new("buffer_set_filename", buffer::test_buffer_set_filename));
    suite.add(TestCase::new("buffer_line", buffer::test_buffer_line));
    suite.add(TestCase::new("buffer_line_out_of_bounds", buffer::test_buffer_line_out_of_bounds));
    suite.add(TestCase::new(
        "buffer_line_mut_marks_modified",
        buffer::test_buffer_line_mut_marks_modified,
    ));
    suite.add(TestCase::new("buffer_is_modified_false", buffer::test_buffer_is_modified_false));
    suite.add(TestCase::new("buffer_mark_saved", buffer::test_buffer_mark_saved));
    suite.add(TestCase::new("buffer_is_readonly_default", buffer::test_buffer_is_readonly_default));
    suite.add(TestCase::new("buffer_set_readonly", buffer::test_buffer_set_readonly));
    suite.add(TestCase::new("buffer_insert_char", buffer::test_buffer_insert_char));
    suite.add(TestCase::new("buffer_delete_char", buffer::test_buffer_delete_char));
    suite.add(TestCase::new(
        "buffer_delete_char_out_of_bounds",
        buffer::test_buffer_delete_char_out_of_bounds,
    ));
    suite.add(TestCase::new("buffer_insert_line", buffer::test_buffer_insert_line));
    suite.add(TestCase::new("buffer_delete_line", buffer::test_buffer_delete_line));
    suite.add(TestCase::new("buffer_delete_line_single", buffer::test_buffer_delete_line_single));
    suite.add(TestCase::new("buffer_split_line", buffer::test_buffer_split_line));
    suite.add(TestCase::new("buffer_join_lines", buffer::test_buffer_join_lines));
    suite.add(TestCase::new("buffer_insert_newline", buffer::test_buffer_insert_newline));
    suite.add(TestCase::new("buffer_backspace_mid_line", buffer::test_buffer_backspace_mid_line));
    suite.add(TestCase::new(
        "buffer_backspace_start_of_line",
        buffer::test_buffer_backspace_start_of_line,
    ));
    suite.add(TestCase::new(
        "buffer_backspace_start_of_buffer",
        buffer::test_buffer_backspace_start_of_buffer,
    ));
    suite.add(TestCase::new("buffer_to_string_single", buffer::test_buffer_to_string_single));
    suite.add(TestCase::new("buffer_to_string_multiple", buffer::test_buffer_to_string_multiple));
    suite.add(TestCase::new("buffer_line_len", buffer::test_buffer_line_len));
    suite.add(TestCase::new(
        "buffer_line_len_out_of_bounds",
        buffer::test_buffer_line_len_out_of_bounds,
    ));
    suite.add(TestCase::new("buffer_total_chars", buffer::test_buffer_total_chars));
    suite.add(TestCase::new("buffer_lines_slice", buffer::test_buffer_lines_slice));
    suite.add(TestCase::new("buffer_default", buffer::test_buffer_default));
    suite.add(TestCase::new("buffer_clone", buffer::test_buffer_clone));
    suite.add(TestCase::new("buffer_debug", buffer::test_buffer_debug));

    // Completion tests (28)
    suite.add(TestCase::new("completer_new", completion::test_completer_new));
    suite.add(TestCase::new(
        "completer_find_completions_empty",
        completion::test_completer_find_completions_empty,
    ));
    suite.add(TestCase::new(
        "completer_find_completions_single_match",
        completion::test_completer_find_completions_single_match,
    ));
    suite.add(TestCase::new(
        "completer_find_completions_multiple_matches",
        completion::test_completer_find_completions_multiple_matches,
    ));
    suite.add(TestCase::new(
        "completer_find_completions_no_match",
        completion::test_completer_find_completions_no_match,
    ));
    suite.add(TestCase::new(
        "completer_complete_single",
        completion::test_completer_complete_single,
    ));
    suite.add(TestCase::new(
        "completer_complete_cycles",
        completion::test_completer_complete_cycles,
    ));
    suite.add(TestCase::new(
        "completer_complete_no_match",
        completion::test_completer_complete_no_match,
    ));
    suite.add(TestCase::new("completer_reset", completion::test_completer_reset));
    suite.add(TestCase::new(
        "completer_is_showing_after_complete",
        completion::test_completer_is_showing_after_complete,
    ));
    suite.add(TestCase::new("completer_prefix_cd", completion::test_completer_prefix_cd));
    suite.add(TestCase::new("completer_prefix_cat", completion::test_completer_prefix_cat));
    suite.add(TestCase::new("completer_prefix_vault", completion::test_completer_prefix_vault));
    suite.add(TestCase::new("completer_prefix_net", completion::test_completer_prefix_net));
    suite.add(TestCase::new("max_completions_constant", completion::test_max_completions_constant));
    suite.add(TestCase::new(
        "max_completion_len_constant",
        completion::test_max_completion_len_constant,
    ));
    suite.add(TestCase::new(
        "completer_complete_with_space_prefix",
        completion::test_completer_complete_with_space_prefix,
    ));
    suite.add(TestCase::new(
        "completer_find_completions_case_sensitive",
        completion::test_completer_find_completions_case_sensitive,
    ));
    suite.add(TestCase::new("completer_find_about", completion::test_completer_find_about));
    suite.add(TestCase::new("completer_find_clear", completion::test_completer_find_clear));
    suite.add(TestCase::new("completer_find_crypto", completion::test_completer_find_crypto));
    suite.add(TestCase::new("completer_find_ping", completion::test_completer_find_ping));
    suite.add(TestCase::new("completer_find_grep", completion::test_completer_find_grep));
    suite.add(TestCase::new(
        "completer_reset_clears_showing",
        completion::test_completer_reset_clears_showing,
    ));
    suite.add(TestCase::new(
        "completer_complete_returns_full_command",
        completion::test_completer_complete_returns_full_command,
    ));

    // Editor tests (68)
    suite.add(TestCase::new("line_new", editor::test_line_new));
    suite.add(TestCase::new("line_from_str", editor::test_line_from_str));
    suite.add(TestCase::new("line_from_str_empty", editor::test_line_from_str_empty));
    suite.add(TestCase::new("line_insert_char", editor::test_line_insert_char));
    suite.add(TestCase::new("line_insert_char_middle", editor::test_line_insert_char_middle));
    suite.add(TestCase::new("line_delete_char", editor::test_line_delete_char));
    suite.add(TestCase::new(
        "line_delete_char_out_of_bounds",
        editor::test_line_delete_char_out_of_bounds,
    ));
    suite.add(TestCase::new("line_split_at", editor::test_line_split_at));
    suite.add(TestCase::new("line_append", editor::test_line_append));
    suite.add(TestCase::new("line_char_at", editor::test_line_char_at));
    suite.add(TestCase::new("line_substring", editor::test_line_substring));
    suite.add(TestCase::new("line_first_non_whitespace", editor::test_line_first_non_whitespace));
    suite.add(TestCase::new(
        "line_first_non_whitespace_no_leading",
        editor::test_line_first_non_whitespace_no_leading,
    ));
    suite.add(TestCase::new("line_last_non_whitespace", editor::test_line_last_non_whitespace));
    suite.add(TestCase::new("line_indent_level", editor::test_line_indent_level));
    suite.add(TestCase::new("line_indent_level_tabs", editor::test_line_indent_level_tabs));
    suite.add(TestCase::new("line_default", editor::test_line_default));
    suite.add(TestCase::new("editor_buffer_new", editor::test_buffer_new));
    suite.add(TestCase::new(
        "editor_buffer_from_string_empty",
        editor::test_buffer_from_string_empty,
    ));
    suite.add(TestCase::new(
        "editor_buffer_from_string_single_line",
        editor::test_buffer_from_string_single_line,
    ));
    suite.add(TestCase::new(
        "editor_buffer_from_string_multiple_lines",
        editor::test_buffer_from_string_multiple_lines,
    ));
    suite.add(TestCase::new("editor_buffer_from_file", editor::test_buffer_from_file));
    suite.add(TestCase::new("editor_buffer_line", editor::test_buffer_line));
    suite.add(TestCase::new(
        "editor_buffer_line_out_of_bounds",
        editor::test_buffer_line_out_of_bounds,
    ));
    suite.add(TestCase::new(
        "editor_buffer_line_mut_marks_modified",
        editor::test_buffer_line_mut_marks_modified,
    ));
    suite.add(TestCase::new("editor_buffer_set_filename", editor::test_buffer_set_filename));
    suite.add(TestCase::new("editor_buffer_mark_saved", editor::test_buffer_mark_saved));
    suite.add(TestCase::new("editor_buffer_readonly", editor::test_buffer_readonly));
    suite.add(TestCase::new("editor_buffer_insert_char", editor::test_buffer_insert_char));
    suite.add(TestCase::new("editor_buffer_delete_char", editor::test_buffer_delete_char));
    suite.add(TestCase::new("editor_buffer_insert_line", editor::test_buffer_insert_line));
    suite.add(TestCase::new("editor_buffer_delete_line", editor::test_buffer_delete_line));
    suite.add(TestCase::new("editor_buffer_split_line", editor::test_buffer_split_line));
    suite.add(TestCase::new("editor_buffer_join_lines", editor::test_buffer_join_lines));
    suite.add(TestCase::new("editor_buffer_backspace", editor::test_buffer_backspace));
    suite.add(TestCase::new("editor_buffer_to_string", editor::test_buffer_to_string));
    suite.add(TestCase::new("editor_buffer_line_len", editor::test_buffer_line_len));
    suite.add(TestCase::new("editor_buffer_default", editor::test_buffer_default));
    suite.add(TestCase::new("mode_normal", editor::test_mode_normal));
    suite.add(TestCase::new("mode_insert", editor::test_mode_insert));
    suite.add(TestCase::new("mode_visual", editor::test_mode_visual));
    suite.add(TestCase::new("mode_visual_line", editor::test_mode_visual_line));
    suite.add(TestCase::new("mode_visual_block", editor::test_mode_visual_block));
    suite.add(TestCase::new("mode_command", editor::test_mode_command));
    suite.add(TestCase::new("mode_replace", editor::test_mode_replace));
    suite.add(TestCase::new("mode_search", editor::test_mode_search));
    suite.add(TestCase::new(
        "mode_status_indicator_normal",
        editor::test_mode_status_indicator_normal,
    ));
    suite.add(TestCase::new(
        "mode_status_indicator_insert",
        editor::test_mode_status_indicator_insert,
    ));
    suite.add(TestCase::new("mode_cursor_style_normal", editor::test_mode_cursor_style_normal));
    suite.add(TestCase::new("mode_cursor_style_insert", editor::test_mode_cursor_style_insert));
    suite.add(TestCase::new("mode_cursor_style_replace", editor::test_mode_cursor_style_replace));
    suite.add(TestCase::new("mode_is_insert_like_insert", editor::test_mode_is_insert_like_insert));
    suite.add(TestCase::new(
        "mode_is_insert_like_replace",
        editor::test_mode_is_insert_like_replace,
    ));
    suite.add(TestCase::new("mode_is_insert_like_normal", editor::test_mode_is_insert_like_normal));
    suite.add(TestCase::new("mode_is_visual", editor::test_mode_is_visual));
    suite.add(TestCase::new("mode_allows_motion", editor::test_mode_allows_motion));
    suite.add(TestCase::new("mode_state_new", editor::test_mode_state_new));
    suite.add(TestCase::new("mode_state_set_mode", editor::test_mode_state_set_mode));
    suite.add(TestCase::new("mode_state_effective_count", editor::test_mode_state_effective_count));
    suite.add(TestCase::new(
        "mode_state_accumulate_count",
        editor::test_mode_state_accumulate_count,
    ));
    suite.add(TestCase::new("mode_state_reset_pending", editor::test_mode_state_reset_pending));
    suite.add(TestCase::new("mode_state_default", editor::test_mode_state_default));
    suite.add(TestCase::new("operator_from_char_delete", editor::test_operator_from_char_delete));
    suite.add(TestCase::new("operator_from_char_yank", editor::test_operator_from_char_yank));
    suite.add(TestCase::new("operator_from_char_change", editor::test_operator_from_char_change));
    suite.add(TestCase::new("operator_from_char_indent", editor::test_operator_from_char_indent));
    suite.add(TestCase::new("operator_from_char_outdent", editor::test_operator_from_char_outdent));
    suite.add(TestCase::new("operator_from_char_invalid", editor::test_operator_from_char_invalid));
    suite.add(TestCase::new("operator_requires_motion", editor::test_operator_requires_motion));
    suite.add(TestCase::new("search_direction_forward", editor::test_search_direction_forward));
    suite.add(TestCase::new("search_direction_backward", editor::test_search_direction_backward));
    suite.add(TestCase::new("motion_result_new", editor::test_motion_result_new));
    suite.add(TestCase::new("motion_result_inclusive", editor::test_motion_result_inclusive));
    suite.add(TestCase::new("motion_result_linewise", editor::test_motion_result_linewise));
    suite.add(TestCase::new("motion_left", editor::test_motion_left));
    suite.add(TestCase::new("motion_right", editor::test_motion_right));
    suite.add(TestCase::new("motion_up", editor::test_motion_up));
    suite.add(TestCase::new("motion_down", editor::test_motion_down));
    suite.add(TestCase::new("motion_word_forward", editor::test_motion_word_forward));
    suite.add(TestCase::new("motion_word_backward", editor::test_motion_word_backward));
    suite.add(TestCase::new("motion_line_start", editor::test_motion_line_start));
    suite.add(TestCase::new("motion_line_end", editor::test_motion_line_end));
    suite.add(TestCase::new("motion_file_start", editor::test_motion_file_start));
    suite.add(TestCase::new("motion_file_end", editor::test_motion_file_end));
    suite.add(TestCase::new("cursor_style_equality", editor::test_cursor_style_equality));

    // Env tests (3)
    suite.add(TestCase::new("env_module_exists", env::test_module_exists));
    suite.add(TestCase::new("env_basic_constants", env::test_basic_constants));
    suite.add(TestCase::new("env_basic_operations", env::test_basic_operations));

    // Expand tests (22)
    suite.add(TestCase::new("expand_no_variables", expand::test_expand_no_variables));
    suite.add(TestCase::new("expand_empty", expand::test_expand_empty));
    suite.add(TestCase::new("expand_dollar_sign_alone", expand::test_expand_dollar_sign_alone));
    suite.add(TestCase::new("expand_exit_status", expand::test_expand_exit_status));
    suite.add(TestCase::new("expand_pid", expand::test_expand_pid));
    suite.add(TestCase::new("expand_text_without_vars", expand::test_expand_text_without_vars));
    suite.add(TestCase::new("expand_preserves_spaces", expand::test_expand_preserves_spaces));
    suite.add(TestCase::new(
        "expand_preserves_special_chars",
        expand::test_expand_preserves_special_chars,
    ));
    suite.add(TestCase::new(
        "expand_braced_var_missing_close",
        expand::test_expand_braced_var_missing_close,
    ));
    suite.add(TestCase::new(
        "expand_multiple_dollar_signs",
        expand::test_expand_multiple_dollar_signs,
    ));
    suite.add(TestCase::new("expand_mixed_content", expand::test_expand_mixed_content));
    suite.add(TestCase::new("expand_consecutive_vars", expand::test_expand_consecutive_vars));
    suite.add(TestCase::new("expand_var_at_start", expand::test_expand_var_at_start));
    suite.add(TestCase::new("expand_var_at_end", expand::test_expand_var_at_end));
    suite.add(TestCase::new("expand_dollar_number", expand::test_expand_dollar_number));
    suite.add(TestCase::new("expand_preserves_quotes", expand::test_expand_preserves_quotes));
    suite.add(TestCase::new(
        "expand_preserves_double_quotes",
        expand::test_expand_preserves_double_quotes,
    ));
    suite.add(TestCase::new("expand_preserves_backslash", expand::test_expand_preserves_backslash));
    suite.add(TestCase::new("expand_long_input", expand::test_expand_long_input));
    suite.add(TestCase::new("expand_newlines", expand::test_expand_newlines));
    suite.add(TestCase::new("expand_tabs", expand::test_expand_tabs));
    suite.add(TestCase::new("expand_unicode_bytes", expand::test_expand_unicode_bytes));

    // History tests (28)
    suite.add(TestCase::new("command_history_new", history::test_command_history_new));
    suite
        .add(TestCase::new("command_history_add_single", history::test_command_history_add_single));
    suite.add(TestCase::new("command_history_add_empty", history::test_command_history_add_empty));
    suite.add(TestCase::new(
        "command_history_add_multiple",
        history::test_command_history_add_multiple,
    ));
    suite.add(TestCase::new(
        "command_history_no_duplicates",
        history::test_command_history_no_duplicates,
    ));
    suite.add(TestCase::new(
        "command_history_duplicates_after_other",
        history::test_command_history_duplicates_after_other,
    ));
    suite
        .add(TestCase::new("command_history_get_single", history::test_command_history_get_single));
    suite.add(TestCase::new(
        "command_history_get_multiple",
        history::test_command_history_get_multiple,
    ));
    suite.add(TestCase::new(
        "command_history_get_out_of_bounds",
        history::test_command_history_get_out_of_bounds,
    ));
    suite.add(TestCase::new("command_history_get_empty", history::test_command_history_get_empty));
    suite.add(TestCase::new(
        "command_history_start_browse",
        history::test_command_history_start_browse,
    ));
    suite.add(TestCase::new(
        "command_history_browse_prev",
        history::test_command_history_browse_prev,
    ));
    suite.add(TestCase::new(
        "command_history_browse_prev_multiple",
        history::test_command_history_browse_prev_multiple,
    ));
    suite.add(TestCase::new(
        "command_history_browse_prev_at_start",
        history::test_command_history_browse_prev_at_start,
    ));
    suite.add(TestCase::new(
        "command_history_browse_next",
        history::test_command_history_browse_next,
    ));
    suite.add(TestCase::new(
        "command_history_browse_next_to_saved",
        history::test_command_history_browse_next_to_saved,
    ));
    suite.add(TestCase::new(
        "command_history_browse_next_not_browsing",
        history::test_command_history_browse_next_not_browsing,
    ));
    suite.add(TestCase::new(
        "command_history_cancel_browse",
        history::test_command_history_cancel_browse,
    ));
    suite.add(TestCase::new("command_history_clear", history::test_command_history_clear));
    suite.add(TestCase::new("command_history_overflow", history::test_command_history_overflow));
    suite.add(TestCase::new(
        "command_history_truncates_long",
        history::test_command_history_truncates_long,
    ));
    suite.add(TestCase::new("history_size_constant", history::test_history_size_constant));
    suite.add(TestCase::new("max_cmd_len_constant", history::test_max_cmd_len_constant));
    suite.add(TestCase::new(
        "command_history_secure_erase",
        history::test_command_history_secure_erase,
    ));
    suite.add(TestCase::new(
        "command_history_browse_empty",
        history::test_command_history_browse_empty,
    ));
    suite.add(TestCase::new(
        "command_history_add_preserves_order",
        history::test_command_history_add_preserves_order,
    ));
    suite.add(TestCase::new(
        "command_history_browsing_resets_on_add",
        history::test_command_history_browsing_resets_on_add,
    ));

    // Input tests (38)
    suite.add(TestCase::new("line_editor_new", input::test_line_editor_new));
    suite.add(TestCase::new("line_editor_reset", input::test_line_editor_reset));
    suite.add(TestCase::new("line_editor_set_row", input::test_line_editor_set_row));
    suite.add(TestCase::new("line_editor_row", input::test_line_editor_row));
    suite.add(TestCase::new(
        "line_editor_get_content_empty",
        input::test_line_editor_get_content_empty,
    ));
    suite.add(TestCase::new("line_editor_get_content", input::test_line_editor_get_content));
    suite.add(TestCase::new("line_editor_length", input::test_line_editor_length));
    suite.add(TestCase::new("line_editor_cursor_pos", input::test_line_editor_cursor_pos));
    suite.add(TestCase::new("line_editor_cursor_col", input::test_line_editor_cursor_col));
    suite.add(TestCase::new(
        "line_editor_cursor_col_after_input",
        input::test_line_editor_cursor_col_after_input,
    ));
    suite.add(TestCase::new("line_editor_set_content", input::test_line_editor_set_content));
    suite.add(TestCase::new(
        "line_editor_set_content_truncates",
        input::test_line_editor_set_content_truncates,
    ));
    suite.add(TestCase::new("line_editor_insert_char", input::test_line_editor_insert_char));
    suite.add(TestCase::new(
        "line_editor_insert_char_multiple",
        input::test_line_editor_insert_char_multiple,
    ));
    suite.add(TestCase::new(
        "line_editor_insert_char_at_middle",
        input::test_line_editor_insert_char_at_middle,
    ));
    suite.add(TestCase::new("line_editor_delete_char", input::test_line_editor_delete_char));
    suite.add(TestCase::new(
        "line_editor_delete_char_at_end",
        input::test_line_editor_delete_char_at_end,
    ));
    suite.add(TestCase::new("line_editor_backspace", input::test_line_editor_backspace));
    suite.add(TestCase::new(
        "line_editor_backspace_at_start",
        input::test_line_editor_backspace_at_start,
    ));
    suite.add(TestCase::new("line_editor_move_left", input::test_line_editor_move_left));
    suite.add(TestCase::new(
        "line_editor_move_left_at_start",
        input::test_line_editor_move_left_at_start,
    ));
    suite.add(TestCase::new("line_editor_move_right", input::test_line_editor_move_right));
    suite.add(TestCase::new(
        "line_editor_move_right_at_end",
        input::test_line_editor_move_right_at_end,
    ));
    suite.add(TestCase::new("line_editor_move_home", input::test_line_editor_move_home));
    suite.add(TestCase::new("line_editor_move_end", input::test_line_editor_move_end));
    suite.add(TestCase::new("line_editor_move_word_left", input::test_line_editor_move_word_left));
    suite.add(TestCase::new(
        "line_editor_move_word_left_at_start",
        input::test_line_editor_move_word_left_at_start,
    ));
    suite
        .add(TestCase::new("line_editor_move_word_right", input::test_line_editor_move_word_right));
    suite.add(TestCase::new(
        "line_editor_delete_word_left",
        input::test_line_editor_delete_word_left,
    ));
    suite.add(TestCase::new(
        "line_editor_delete_word_left_at_start",
        input::test_line_editor_delete_word_left_at_start,
    ));
    suite.add(TestCase::new("line_editor_delete_to_end", input::test_line_editor_delete_to_end));
    suite
        .add(TestCase::new("line_editor_delete_to_start", input::test_line_editor_delete_to_start));
    suite.add(TestCase::new(
        "line_editor_delete_to_start_at_beginning",
        input::test_line_editor_delete_to_start_at_beginning,
    ));
    suite.add(TestCase::new("line_editor_clear_line", input::test_line_editor_clear_line));
    suite.add(TestCase::new("max_input_len_constant", input::test_max_input_len_constant));
    suite.add(TestCase::new("prompt_len_constant", input::test_prompt_len_constant));
    suite.add(TestCase::new(
        "line_editor_insert_at_max_length",
        input::test_line_editor_insert_at_max_length,
    ));

    // Pipeline tests (28)
    suite.add(TestCase::new("redirect_type_none", pipeline::test_redirect_type_none));
    suite.add(TestCase::new("redirect_type_write", pipeline::test_redirect_type_write));
    suite.add(TestCase::new("redirect_type_append", pipeline::test_redirect_type_append));
    suite.add(TestCase::new("redirect_type_input", pipeline::test_redirect_type_input));
    suite.add(TestCase::new("redirect_type_equality", pipeline::test_redirect_type_equality));
    suite.add(TestCase::new("pipeline_parse_simple", pipeline::test_pipeline_parse_simple));
    suite.add(TestCase::new("pipeline_parse_with_args", pipeline::test_pipeline_parse_with_args));
    suite.add(TestCase::new("pipeline_parse_two_stages", pipeline::test_pipeline_parse_two_stages));
    suite.add(TestCase::new(
        "pipeline_parse_three_stages",
        pipeline::test_pipeline_parse_three_stages,
    ));
    suite.add(TestCase::new(
        "pipeline_parse_redirect_write",
        pipeline::test_pipeline_parse_redirect_write,
    ));
    suite.add(TestCase::new(
        "pipeline_parse_redirect_append",
        pipeline::test_pipeline_parse_redirect_append,
    ));
    suite.add(TestCase::new(
        "pipeline_parse_redirect_input",
        pipeline::test_pipeline_parse_redirect_input,
    ));
    suite.add(TestCase::new("pipeline_is_simple_true", pipeline::test_pipeline_is_simple_true));
    suite.add(TestCase::new(
        "pipeline_is_simple_false_with_pipe",
        pipeline::test_pipeline_is_simple_false_with_pipe,
    ));
    suite.add(TestCase::new(
        "pipeline_is_simple_false_with_redirect",
        pipeline::test_pipeline_is_simple_false_with_redirect,
    ));
    suite.add(TestCase::new("pipeline_has_pipes_false", pipeline::test_pipeline_has_pipes_false));
    suite.add(TestCase::new("pipeline_has_pipes_true", pipeline::test_pipeline_has_pipes_true));
    suite.add(TestCase::new("pipeline_parse_empty", pipeline::test_pipeline_parse_empty));
    suite.add(TestCase::new(
        "pipeline_parse_whitespace_only",
        pipeline::test_pipeline_parse_whitespace_only,
    ));
    suite.add(TestCase::new(
        "pipeline_parse_trims_whitespace",
        pipeline::test_pipeline_parse_trims_whitespace,
    ));
    suite.add(TestCase::new(
        "pipeline_parse_pipe_with_spaces",
        pipeline::test_pipeline_parse_pipe_with_spaces,
    ));
    suite.add(TestCase::new(
        "pipeline_parse_redirect_no_target",
        pipeline::test_pipeline_parse_redirect_no_target,
    ));
    suite.add(TestCase::new(
        "pipeline_parse_multiple_pipes_and_redirect",
        pipeline::test_pipeline_parse_multiple_pipes_and_redirect,
    ));
    suite.add(TestCase::new(
        "pipeline_stage_command_preserved",
        pipeline::test_pipeline_stage_command_preserved,
    ));
    suite.add(TestCase::new(
        "pipeline_redirect_type_copy",
        pipeline::test_pipeline_redirect_type_copy,
    ));
    suite.add(TestCase::new(
        "pipeline_redirect_type_clone",
        pipeline::test_pipeline_redirect_type_clone,
    ));
    suite.add(TestCase::new(
        "pipeline_parse_long_command",
        pipeline::test_pipeline_parse_long_command,
    ));
    suite.add(TestCase::new("pipeline_parse_tabs", pipeline::test_pipeline_parse_tabs));

    // Script tests (3)
    suite.add(TestCase::new("script_module_exists", script::test_module_exists));
    suite.add(TestCase::new("script_basic_constants", script::test_basic_constants));
    suite.add(TestCase::new("script_basic_operations", script::test_basic_operations));

    // Utils tests (35)
    suite.add(TestCase::new("trim_bytes_empty", utils::test_trim_bytes_empty));
    suite.add(TestCase::new("trim_bytes_no_spaces", utils::test_trim_bytes_no_spaces));
    suite.add(TestCase::new("trim_bytes_leading_spaces", utils::test_trim_bytes_leading_spaces));
    suite.add(TestCase::new("trim_bytes_trailing_spaces", utils::test_trim_bytes_trailing_spaces));
    suite.add(TestCase::new("trim_bytes_both_sides", utils::test_trim_bytes_both_sides));
    suite.add(TestCase::new("trim_bytes_only_spaces", utils::test_trim_bytes_only_spaces));
    suite.add(TestCase::new("trim_bytes_single_char", utils::test_trim_bytes_single_char));
    suite.add(TestCase::new(
        "trim_bytes_single_space_char",
        utils::test_trim_bytes_single_space_char,
    ));
    suite.add(TestCase::new("trim_bytes_internal_spaces", utils::test_trim_bytes_internal_spaces));
    suite.add(TestCase::new(
        "trim_bytes_multiple_internal_spaces",
        utils::test_trim_bytes_multiple_internal_spaces,
    ));
    suite.add(TestCase::new("starts_with_true", utils::test_starts_with_true));
    suite.add(TestCase::new("starts_with_false", utils::test_starts_with_false));
    suite.add(TestCase::new("starts_with_exact", utils::test_starts_with_exact));
    suite.add(TestCase::new("starts_with_empty_prefix", utils::test_starts_with_empty_prefix));
    suite.add(TestCase::new("starts_with_empty_string", utils::test_starts_with_empty_string));
    suite.add(TestCase::new("starts_with_longer_prefix", utils::test_starts_with_longer_prefix));
    suite.add(TestCase::new("starts_with_single_char", utils::test_starts_with_single_char));
    suite.add(TestCase::new("format_size_bytes", utils::test_format_size_bytes));
    suite.add(TestCase::new("format_size_kilobytes", utils::test_format_size_kilobytes));
    suite.add(TestCase::new("format_size_megabytes", utils::test_format_size_megabytes));
    suite.add(TestCase::new("format_size_gigabytes", utils::test_format_size_gigabytes));
    suite.add(TestCase::new("format_size_zero", utils::test_format_size_zero));
    suite.add(TestCase::new("format_size_one", utils::test_format_size_one));
    suite.add(TestCase::new("format_num_unit_zero", utils::test_format_num_unit_zero));
    suite.add(TestCase::new("format_num_unit_with_frac", utils::test_format_num_unit_with_frac));
    suite.add(TestCase::new("format_num_unit_large", utils::test_format_num_unit_large));
    suite.add(TestCase::new("format_decimal_zero", utils::test_format_decimal_zero));
    suite.add(TestCase::new("format_decimal_single", utils::test_format_decimal_single));
    suite.add(TestCase::new("format_decimal_large", utils::test_format_decimal_large));
    suite.add(TestCase::new("format_num_simple_zero", utils::test_format_num_simple_zero));
    suite.add(TestCase::new("format_num_simple_positive", utils::test_format_num_simple_positive));
    suite.add(TestCase::new("format_num_simple_large", utils::test_format_num_simple_large));
    suite.add(TestCase::new("write_right_aligned", utils::test_write_right_aligned));
    suite
        .add(TestCase::new("write_right_aligned_padding", utils::test_write_right_aligned_padding));
    suite.add(TestCase::new("write_size_col", utils::test_write_size_col));
    suite.add(TestCase::new("write_size_col_large", utils::test_write_size_col_large));
    suite.add(TestCase::new("format_hex_byte_zero", utils::test_format_hex_byte_zero));
    suite.add(TestCase::new("format_hex_byte_ff", utils::test_format_hex_byte_ff));
    suite.add(TestCase::new("format_hex_byte_mid", utils::test_format_hex_byte_mid));
    suite.add(TestCase::new("format_hex_byte_low", utils::test_format_hex_byte_low));
    suite.add(TestCase::new("format_hex_byte_high", utils::test_format_hex_byte_high));

    suite.run()
}
