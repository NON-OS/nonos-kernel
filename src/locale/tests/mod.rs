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

pub mod api_tests;
pub mod language_tests;
pub mod strings_tests;

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("locale");

    // api_tests (63 tests)
    suite.add(TestCase::new("get_returns_byte_slice", api_tests::test_get_returns_byte_slice));
    suite.add(TestCase::new("get_settings_string", api_tests::test_get_settings_string));
    suite.add(TestCase::new("get_system_string", api_tests::test_get_system_string));
    suite.add(TestCase::new("get_network_string", api_tests::test_get_network_string));
    suite.add(TestCase::new("get_privacy_string", api_tests::test_get_privacy_string));
    suite.add(TestCase::new("get_appearance_string", api_tests::test_get_appearance_string));
    suite.add(TestCase::new("get_power_string", api_tests::test_get_power_string));
    suite.add(TestCase::new("get_language_string", api_tests::test_get_language_string));
    suite.add(TestCase::new("get_timezone_string", api_tests::test_get_timezone_string));
    suite.add(TestCase::new("get_theme_string", api_tests::test_get_theme_string));
    suite.add(TestCase::new("get_dark_string", api_tests::test_get_dark_string));
    suite.add(TestCase::new("get_light_string", api_tests::test_get_light_string));
    suite.add(TestCase::new("get_auto_string", api_tests::test_get_auto_string));
    suite.add(TestCase::new("get_files_string", api_tests::test_get_files_string));
    suite.add(TestCase::new("get_terminal_string", api_tests::test_get_terminal_string));
    suite.add(TestCase::new("get_browser_string", api_tests::test_get_browser_string));
    suite.add(TestCase::new("get_wallet_string", api_tests::test_get_wallet_string));
    suite.add(TestCase::new("get_cancel_string", api_tests::test_get_cancel_string));
    suite.add(TestCase::new("get_ok_string", api_tests::test_get_ok_string));
    suite.add(TestCase::new("get_apply_string", api_tests::test_get_apply_string));
    suite.add(TestCase::new("get_save_string", api_tests::test_get_save_string));
    suite.add(TestCase::new("get_delete_string", api_tests::test_get_delete_string));
    suite.add(TestCase::new("get_rename_string", api_tests::test_get_rename_string));
    suite.add(TestCase::new("get_newfolder_string", api_tests::test_get_newfolder_string));
    suite.add(TestCase::new("get_newfile_string", api_tests::test_get_newfile_string));
    suite.add(TestCase::new("get_copy_string", api_tests::test_get_copy_string));
    suite.add(TestCase::new("get_paste_string", api_tests::test_get_paste_string));
    suite.add(TestCase::new("get_cut_string", api_tests::test_get_cut_string));
    suite.add(TestCase::new("get_refresh_string", api_tests::test_get_refresh_string));
    suite.add(TestCase::new("get_about_string", api_tests::test_get_about_string));
    suite.add(TestCase::new("get_help_string", api_tests::test_get_help_string));
    suite.add(TestCase::new("get_shutdown_string", api_tests::test_get_shutdown_string));
    suite.add(TestCase::new("get_restart_string", api_tests::test_get_restart_string));
    suite.add(TestCase::new("get_sleep_string", api_tests::test_get_sleep_string));
    suite.add(TestCase::new("get_logout_string", api_tests::test_get_logout_string));
    suite.add(TestCase::new("get_back_string", api_tests::test_get_back_string));
    suite.add(TestCase::new("get_forward_string", api_tests::test_get_forward_string));
    suite.add(TestCase::new("get_kernel_string", api_tests::test_get_kernel_string));
    suite
        .add(TestCase::new("get_lang_returns_language", api_tests::test_get_lang_returns_language));
    suite.add(TestCase::new("set_lang_english", api_tests::test_set_lang_english));
    suite.add(TestCase::new("set_lang_spanish", api_tests::test_set_lang_spanish));
    suite.add(TestCase::new("set_lang_french", api_tests::test_set_lang_french));
    suite.add(TestCase::new("set_lang_german", api_tests::test_set_lang_german));
    suite.add(TestCase::new("set_lang_chinese", api_tests::test_set_lang_chinese));
    suite.add(TestCase::new("set_lang_japanese", api_tests::test_set_lang_japanese));
    suite.add(TestCase::new("get_spanish_settings", api_tests::test_get_spanish_settings));
    suite.add(TestCase::new("get_spanish_system", api_tests::test_get_spanish_system));
    suite.add(TestCase::new("get_spanish_network", api_tests::test_get_spanish_network));
    suite.add(TestCase::new("get_spanish_privacy", api_tests::test_get_spanish_privacy));
    suite.add(TestCase::new("get_french_settings", api_tests::test_get_french_settings));
    suite.add(TestCase::new("get_french_system", api_tests::test_get_french_system));
    suite.add(TestCase::new("get_french_network", api_tests::test_get_french_network));
    suite.add(TestCase::new("get_french_privacy", api_tests::test_get_french_privacy));
    suite.add(TestCase::new("get_german_settings", api_tests::test_get_german_settings));
    suite.add(TestCase::new("get_german_system", api_tests::test_get_german_system));
    suite.add(TestCase::new("get_german_network", api_tests::test_get_german_network));
    suite.add(TestCase::new("get_german_privacy", api_tests::test_get_german_privacy));
    suite.add(TestCase::new("get_chinese_settings", api_tests::test_get_chinese_settings));
    suite.add(TestCase::new("get_japanese_settings", api_tests::test_get_japanese_settings));
    suite.add(TestCase::new("language_switching", api_tests::test_language_switching));
    suite.add(TestCase::new(
        "init_from_settings_callable",
        api_tests::test_init_from_settings_callable,
    ));

    // language_tests (72 tests)
    suite.add(TestCase::new("language_english_value", language_tests::test_language_english_value));
    suite.add(TestCase::new("language_spanish_value", language_tests::test_language_spanish_value));
    suite.add(TestCase::new("language_french_value", language_tests::test_language_french_value));
    suite.add(TestCase::new("language_german_value", language_tests::test_language_german_value));
    suite.add(TestCase::new("language_chinese_value", language_tests::test_language_chinese_value));
    suite.add(TestCase::new(
        "language_japanese_value",
        language_tests::test_language_japanese_value,
    ));
    suite.add(TestCase::new("language_from_0", language_tests::test_language_from_0));
    suite.add(TestCase::new("language_from_1", language_tests::test_language_from_1));
    suite.add(TestCase::new("language_from_2", language_tests::test_language_from_2));
    suite.add(TestCase::new("language_from_3", language_tests::test_language_from_3));
    suite.add(TestCase::new("language_from_4", language_tests::test_language_from_4));
    suite.add(TestCase::new("language_from_5", language_tests::test_language_from_5));
    suite.add(TestCase::new(
        "language_from_invalid_defaults_english",
        language_tests::test_language_from_invalid_defaults_english,
    ));
    suite.add(TestCase::new(
        "language_from_large_value_defaults_english",
        language_tests::test_language_from_large_value_defaults_english,
    ));
    suite.add(TestCase::new(
        "language_from_100_defaults_english",
        language_tests::test_language_from_100_defaults_english,
    ));
    suite.add(TestCase::new("language_clone", language_tests::test_language_clone));
    suite.add(TestCase::new("language_copy", language_tests::test_language_copy));
    suite.add(TestCase::new("language_eq_same", language_tests::test_language_eq_same));
    suite.add(TestCase::new("language_eq_different", language_tests::test_language_eq_different));
    suite.add(TestCase::new("language_partial_eq", language_tests::test_language_partial_eq));
    suite.add(TestCase::new("language_not_eq", language_tests::test_language_not_eq));
    suite.add(TestCase::new("language_repr_u8", language_tests::test_language_repr_u8));
    suite.add(TestCase::new(
        "set_and_get_lang_english",
        language_tests::test_set_and_get_lang_english,
    ));
    suite.add(TestCase::new(
        "set_and_get_lang_spanish",
        language_tests::test_set_and_get_lang_spanish,
    ));
    suite.add(TestCase::new(
        "set_and_get_lang_french",
        language_tests::test_set_and_get_lang_french,
    ));
    suite.add(TestCase::new(
        "set_and_get_lang_german",
        language_tests::test_set_and_get_lang_german,
    ));
    suite.add(TestCase::new(
        "set_and_get_lang_chinese",
        language_tests::test_set_and_get_lang_chinese,
    ));
    suite.add(TestCase::new(
        "set_and_get_lang_japanese",
        language_tests::test_set_and_get_lang_japanese,
    ));
    suite.add(TestCase::new(
        "language_switch_affects_strings",
        language_tests::test_language_switch_affects_strings,
    ));
    suite.add(TestCase::new(
        "language_roundtrip_english",
        language_tests::test_language_roundtrip_english,
    ));
    suite.add(TestCase::new(
        "language_roundtrip_spanish",
        language_tests::test_language_roundtrip_spanish,
    ));
    suite.add(TestCase::new(
        "language_roundtrip_french",
        language_tests::test_language_roundtrip_french,
    ));
    suite.add(TestCase::new(
        "language_roundtrip_german",
        language_tests::test_language_roundtrip_german,
    ));
    suite.add(TestCase::new(
        "language_roundtrip_chinese",
        language_tests::test_language_roundtrip_chinese,
    ));
    suite.add(TestCase::new(
        "language_roundtrip_japanese",
        language_tests::test_language_roundtrip_japanese,
    ));
    suite.add(TestCase::new(
        "multiple_language_switches",
        language_tests::test_multiple_language_switches,
    ));
    suite.add(TestCase::new(
        "language_all_variants_accessible",
        language_tests::test_language_all_variants_accessible,
    ));
    suite.add(TestCase::new(
        "language_from_all_valid_values",
        language_tests::test_language_from_all_valid_values,
    ));
    suite.add(TestCase::new("spanish_ok_string", language_tests::test_spanish_ok_string));
    suite.add(TestCase::new("spanish_save_string", language_tests::test_spanish_save_string));
    suite.add(TestCase::new("spanish_delete_string", language_tests::test_spanish_delete_string));
    suite.add(TestCase::new("spanish_copy_string", language_tests::test_spanish_copy_string));
    suite.add(TestCase::new("spanish_paste_string", language_tests::test_spanish_paste_string));
    suite.add(TestCase::new("french_ok_string", language_tests::test_french_ok_string));
    suite.add(TestCase::new("french_save_string", language_tests::test_french_save_string));
    suite.add(TestCase::new("french_delete_string", language_tests::test_french_delete_string));
    suite.add(TestCase::new("french_copy_string", language_tests::test_french_copy_string));
    suite.add(TestCase::new("french_paste_string", language_tests::test_french_paste_string));
    suite.add(TestCase::new("german_ok_string", language_tests::test_german_ok_string));
    suite.add(TestCase::new("german_save_string", language_tests::test_german_save_string));
    suite.add(TestCase::new("german_delete_string", language_tests::test_german_delete_string));
    suite.add(TestCase::new("german_copy_string", language_tests::test_german_copy_string));
    suite.add(TestCase::new("german_paste_string", language_tests::test_german_paste_string));
    suite.add(TestCase::new(
        "spanish_shutdown_string",
        language_tests::test_spanish_shutdown_string,
    ));
    suite.add(TestCase::new("spanish_restart_string", language_tests::test_spanish_restart_string));
    suite.add(TestCase::new("french_shutdown_string", language_tests::test_french_shutdown_string));
    suite.add(TestCase::new("french_restart_string", language_tests::test_french_restart_string));
    suite.add(TestCase::new("german_shutdown_string", language_tests::test_german_shutdown_string));
    suite.add(TestCase::new("german_restart_string", language_tests::test_german_restart_string));
    suite.add(TestCase::new(
        "spanish_appearance_string",
        language_tests::test_spanish_appearance_string,
    ));
    suite.add(TestCase::new(
        "french_appearance_string",
        language_tests::test_french_appearance_string,
    ));
    suite.add(TestCase::new(
        "german_appearance_string",
        language_tests::test_german_appearance_string,
    ));
    suite.add(TestCase::new("spanish_power_string", language_tests::test_spanish_power_string));
    suite.add(TestCase::new("french_power_string", language_tests::test_french_power_string));
    suite.add(TestCase::new("german_power_string", language_tests::test_german_power_string));

    // strings_tests (69 tests)
    suite.add(TestCase::new("string_id_settings", strings_tests::test_string_id_settings));
    suite.add(TestCase::new("string_id_system", strings_tests::test_string_id_system));
    suite.add(TestCase::new("string_id_network", strings_tests::test_string_id_network));
    suite.add(TestCase::new("string_id_privacy", strings_tests::test_string_id_privacy));
    suite.add(TestCase::new("string_id_appearance", strings_tests::test_string_id_appearance));
    suite.add(TestCase::new("string_id_power", strings_tests::test_string_id_power));
    suite.add(TestCase::new("string_id_language", strings_tests::test_string_id_language));
    suite.add(TestCase::new("string_id_timezone", strings_tests::test_string_id_timezone));
    suite.add(TestCase::new("string_id_theme", strings_tests::test_string_id_theme));
    suite.add(TestCase::new("string_id_dark", strings_tests::test_string_id_dark));
    suite.add(TestCase::new("string_id_light", strings_tests::test_string_id_light));
    suite.add(TestCase::new("string_id_auto", strings_tests::test_string_id_auto));
    suite.add(TestCase::new("string_id_files", strings_tests::test_string_id_files));
    suite.add(TestCase::new("string_id_terminal", strings_tests::test_string_id_terminal));
    suite.add(TestCase::new("string_id_browser", strings_tests::test_string_id_browser));
    suite.add(TestCase::new("string_id_wallet", strings_tests::test_string_id_wallet));
    suite.add(TestCase::new("string_id_cancel", strings_tests::test_string_id_cancel));
    suite.add(TestCase::new("string_id_ok", strings_tests::test_string_id_ok));
    suite.add(TestCase::new("string_id_apply", strings_tests::test_string_id_apply));
    suite.add(TestCase::new("string_id_save", strings_tests::test_string_id_save));
    suite.add(TestCase::new("string_id_delete", strings_tests::test_string_id_delete));
    suite.add(TestCase::new("string_id_rename", strings_tests::test_string_id_rename));
    suite.add(TestCase::new("string_id_newfolder", strings_tests::test_string_id_newfolder));
    suite.add(TestCase::new("string_id_newfile", strings_tests::test_string_id_newfile));
    suite.add(TestCase::new("string_id_copy", strings_tests::test_string_id_copy));
    suite.add(TestCase::new("string_id_paste", strings_tests::test_string_id_paste));
    suite.add(TestCase::new("string_id_cut", strings_tests::test_string_id_cut));
    suite.add(TestCase::new("string_id_refresh", strings_tests::test_string_id_refresh));
    suite.add(TestCase::new("string_id_about", strings_tests::test_string_id_about));
    suite.add(TestCase::new("string_id_help", strings_tests::test_string_id_help));
    suite.add(TestCase::new("string_id_shutdown", strings_tests::test_string_id_shutdown));
    suite.add(TestCase::new("string_id_restart", strings_tests::test_string_id_restart));
    suite.add(TestCase::new("string_id_sleep", strings_tests::test_string_id_sleep));
    suite.add(TestCase::new("string_id_logout", strings_tests::test_string_id_logout));
    suite.add(TestCase::new("string_id_back", strings_tests::test_string_id_back));
    suite.add(TestCase::new("string_id_forward", strings_tests::test_string_id_forward));
    suite.add(TestCase::new("string_id_kernel", strings_tests::test_string_id_kernel));
    suite.add(TestCase::new("string_id_clone", strings_tests::test_string_id_clone));
    suite.add(TestCase::new("string_id_copy_trait", strings_tests::test_string_id_copy_trait));
    suite.add(TestCase::new("string_id_equality", strings_tests::test_string_id_equality));
    suite.add(TestCase::new("strings_en_length", strings_tests::test_strings_en_length));
    suite.add(TestCase::new("strings_es_length", strings_tests::test_strings_es_length));
    suite.add(TestCase::new("strings_fr_length", strings_tests::test_strings_fr_length));
    suite.add(TestCase::new("strings_de_length", strings_tests::test_strings_de_length));
    suite.add(TestCase::new("strings_zh_length", strings_tests::test_strings_zh_length));
    suite.add(TestCase::new("strings_ja_length", strings_tests::test_strings_ja_length));
    suite.add(TestCase::new("strings_en_settings", strings_tests::test_strings_en_settings));
    suite.add(TestCase::new("strings_en_system", strings_tests::test_strings_en_system));
    suite.add(TestCase::new("strings_en_network", strings_tests::test_strings_en_network));
    suite.add(TestCase::new("strings_en_privacy", strings_tests::test_strings_en_privacy));
    suite.add(TestCase::new("strings_en_cancel", strings_tests::test_strings_en_cancel));
    suite.add(TestCase::new("strings_en_ok", strings_tests::test_strings_en_ok));
    suite.add(TestCase::new("strings_en_kernel", strings_tests::test_strings_en_kernel));
    suite.add(TestCase::new("strings_es_settings", strings_tests::test_strings_es_settings));
    suite.add(TestCase::new("strings_es_system", strings_tests::test_strings_es_system));
    suite.add(TestCase::new("strings_es_network", strings_tests::test_strings_es_network));
    suite.add(TestCase::new("strings_es_cancel", strings_tests::test_strings_es_cancel));
    suite.add(TestCase::new("strings_fr_settings", strings_tests::test_strings_fr_settings));
    suite.add(TestCase::new("strings_fr_system", strings_tests::test_strings_fr_system));
    suite.add(TestCase::new("strings_fr_network", strings_tests::test_strings_fr_network));
    suite.add(TestCase::new("strings_fr_cancel", strings_tests::test_strings_fr_cancel));
    suite.add(TestCase::new("strings_de_settings", strings_tests::test_strings_de_settings));
    suite.add(TestCase::new("strings_de_system", strings_tests::test_strings_de_system));
    suite.add(TestCase::new("strings_de_network", strings_tests::test_strings_de_network));
    suite.add(TestCase::new("strings_de_cancel", strings_tests::test_strings_de_cancel));
    suite.add(TestCase::new(
        "all_languages_have_same_string_count",
        strings_tests::test_all_languages_have_same_string_count,
    ));
    suite.add(TestCase::new(
        "all_strings_en_non_empty",
        strings_tests::test_all_strings_en_non_empty,
    ));
    suite.add(TestCase::new(
        "all_strings_es_non_empty",
        strings_tests::test_all_strings_es_non_empty,
    ));
    suite.add(TestCase::new(
        "all_strings_fr_non_empty",
        strings_tests::test_all_strings_fr_non_empty,
    ));
    suite.add(TestCase::new(
        "all_strings_de_non_empty",
        strings_tests::test_all_strings_de_non_empty,
    ));
    suite.add(TestCase::new("string_id_sequential", strings_tests::test_string_id_sequential));
    suite.add(TestCase::new("string_id_max", strings_tests::test_string_id_max));
    suite.add(TestCase::new("strings_valid_utf8", strings_tests::test_strings_valid_utf8));

    suite.run()
}
