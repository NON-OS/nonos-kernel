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

use crate::locale::*;

#[test]
fn test_get_returns_byte_slice() {
    let result = get(StringId::Settings);
    assert!(!result.is_empty());
}

#[test]
fn test_get_settings_string() {
    set_lang(Language::English);
    let result = get(StringId::Settings);
    assert_eq!(result, b"Settings");
}

#[test]
fn test_get_system_string() {
    set_lang(Language::English);
    let result = get(StringId::System);
    assert_eq!(result, b"System");
}

#[test]
fn test_get_network_string() {
    set_lang(Language::English);
    let result = get(StringId::Network);
    assert_eq!(result, b"Network");
}

#[test]
fn test_get_privacy_string() {
    set_lang(Language::English);
    let result = get(StringId::Privacy);
    assert_eq!(result, b"Privacy");
}

#[test]
fn test_get_appearance_string() {
    set_lang(Language::English);
    let result = get(StringId::Appearance);
    assert_eq!(result, b"Appearance");
}

#[test]
fn test_get_power_string() {
    set_lang(Language::English);
    let result = get(StringId::Power);
    assert_eq!(result, b"Power");
}

#[test]
fn test_get_language_string() {
    set_lang(Language::English);
    let result = get(StringId::Language);
    assert_eq!(result, b"Language");
}

#[test]
fn test_get_timezone_string() {
    set_lang(Language::English);
    let result = get(StringId::Timezone);
    assert_eq!(result, b"Timezone");
}

#[test]
fn test_get_theme_string() {
    set_lang(Language::English);
    let result = get(StringId::Theme);
    assert_eq!(result, b"Theme");
}

#[test]
fn test_get_dark_string() {
    set_lang(Language::English);
    let result = get(StringId::Dark);
    assert_eq!(result, b"Dark");
}

#[test]
fn test_get_light_string() {
    set_lang(Language::English);
    let result = get(StringId::Light);
    assert_eq!(result, b"Light");
}

#[test]
fn test_get_auto_string() {
    set_lang(Language::English);
    let result = get(StringId::Auto);
    assert_eq!(result, b"Auto");
}

#[test]
fn test_get_files_string() {
    set_lang(Language::English);
    let result = get(StringId::Files);
    assert_eq!(result, b"Files");
}

#[test]
fn test_get_terminal_string() {
    set_lang(Language::English);
    let result = get(StringId::Terminal);
    assert_eq!(result, b"Terminal");
}

#[test]
fn test_get_browser_string() {
    set_lang(Language::English);
    let result = get(StringId::Browser);
    assert_eq!(result, b"Browser");
}

#[test]
fn test_get_wallet_string() {
    set_lang(Language::English);
    let result = get(StringId::Wallet);
    assert_eq!(result, b"Wallet");
}

#[test]
fn test_get_cancel_string() {
    set_lang(Language::English);
    let result = get(StringId::Cancel);
    assert_eq!(result, b"Cancel");
}

#[test]
fn test_get_ok_string() {
    set_lang(Language::English);
    let result = get(StringId::Ok);
    assert_eq!(result, b"OK");
}

#[test]
fn test_get_apply_string() {
    set_lang(Language::English);
    let result = get(StringId::Apply);
    assert_eq!(result, b"Apply");
}

#[test]
fn test_get_save_string() {
    set_lang(Language::English);
    let result = get(StringId::Save);
    assert_eq!(result, b"Save");
}

#[test]
fn test_get_delete_string() {
    set_lang(Language::English);
    let result = get(StringId::Delete);
    assert_eq!(result, b"Delete");
}

#[test]
fn test_get_rename_string() {
    set_lang(Language::English);
    let result = get(StringId::Rename);
    assert_eq!(result, b"Rename");
}

#[test]
fn test_get_newfolder_string() {
    set_lang(Language::English);
    let result = get(StringId::NewFolder);
    assert_eq!(result, b"New Folder");
}

#[test]
fn test_get_newfile_string() {
    set_lang(Language::English);
    let result = get(StringId::NewFile);
    assert_eq!(result, b"New File");
}

#[test]
fn test_get_copy_string() {
    set_lang(Language::English);
    let result = get(StringId::Copy);
    assert_eq!(result, b"Copy");
}

#[test]
fn test_get_paste_string() {
    set_lang(Language::English);
    let result = get(StringId::Paste);
    assert_eq!(result, b"Paste");
}

#[test]
fn test_get_cut_string() {
    set_lang(Language::English);
    let result = get(StringId::Cut);
    assert_eq!(result, b"Cut");
}

#[test]
fn test_get_refresh_string() {
    set_lang(Language::English);
    let result = get(StringId::Refresh);
    assert_eq!(result, b"Refresh");
}

#[test]
fn test_get_about_string() {
    set_lang(Language::English);
    let result = get(StringId::About);
    assert_eq!(result, b"About");
}

#[test]
fn test_get_help_string() {
    set_lang(Language::English);
    let result = get(StringId::Help);
    assert_eq!(result, b"Help");
}

#[test]
fn test_get_shutdown_string() {
    set_lang(Language::English);
    let result = get(StringId::Shutdown);
    assert_eq!(result, b"Shutdown");
}

#[test]
fn test_get_restart_string() {
    set_lang(Language::English);
    let result = get(StringId::Restart);
    assert_eq!(result, b"Restart");
}

#[test]
fn test_get_sleep_string() {
    set_lang(Language::English);
    let result = get(StringId::Sleep);
    assert_eq!(result, b"Sleep");
}

#[test]
fn test_get_logout_string() {
    set_lang(Language::English);
    let result = get(StringId::Logout);
    assert_eq!(result, b"Logout");
}

#[test]
fn test_get_back_string() {
    set_lang(Language::English);
    let result = get(StringId::Back);
    assert_eq!(result, b"Back");
}

#[test]
fn test_get_forward_string() {
    set_lang(Language::English);
    let result = get(StringId::Forward);
    assert_eq!(result, b"Forward");
}

#[test]
fn test_get_kernel_string() {
    set_lang(Language::English);
    let result = get(StringId::Kernel);
    assert_eq!(result, b"Kernel");
}

#[test]
fn test_get_lang_returns_language() {
    set_lang(Language::English);
    let lang = get_lang();
    assert_eq!(lang, Language::English);
}

#[test]
fn test_set_lang_english() {
    set_lang(Language::English);
    assert_eq!(get_lang(), Language::English);
}

#[test]
fn test_set_lang_spanish() {
    set_lang(Language::Spanish);
    assert_eq!(get_lang(), Language::Spanish);
}

#[test]
fn test_set_lang_french() {
    set_lang(Language::French);
    assert_eq!(get_lang(), Language::French);
}

#[test]
fn test_set_lang_german() {
    set_lang(Language::German);
    assert_eq!(get_lang(), Language::German);
}

#[test]
fn test_set_lang_chinese() {
    set_lang(Language::Chinese);
    assert_eq!(get_lang(), Language::Chinese);
}

#[test]
fn test_set_lang_japanese() {
    set_lang(Language::Japanese);
    assert_eq!(get_lang(), Language::Japanese);
}

#[test]
fn test_get_spanish_settings() {
    set_lang(Language::Spanish);
    let result = get(StringId::Settings);
    assert_eq!(result, b"Ajustes");
}

#[test]
fn test_get_spanish_system() {
    set_lang(Language::Spanish);
    let result = get(StringId::System);
    assert_eq!(result, b"Sistema");
}

#[test]
fn test_get_spanish_network() {
    set_lang(Language::Spanish);
    let result = get(StringId::Network);
    assert_eq!(result, b"Red");
}

#[test]
fn test_get_spanish_privacy() {
    set_lang(Language::Spanish);
    let result = get(StringId::Privacy);
    assert_eq!(result, b"Privacidad");
}

#[test]
fn test_get_french_settings() {
    set_lang(Language::French);
    let result = get(StringId::Settings);
    assert_eq!(result, b"Parametres");
}

#[test]
fn test_get_french_system() {
    set_lang(Language::French);
    let result = get(StringId::System);
    assert_eq!(result, b"Systeme");
}

#[test]
fn test_get_french_network() {
    set_lang(Language::French);
    let result = get(StringId::Network);
    assert_eq!(result, b"Reseau");
}

#[test]
fn test_get_french_privacy() {
    set_lang(Language::French);
    let result = get(StringId::Privacy);
    assert_eq!(result, b"Confidentialite");
}

#[test]
fn test_get_german_settings() {
    set_lang(Language::German);
    let result = get(StringId::Settings);
    assert_eq!(result, b"Einstellungen");
}

#[test]
fn test_get_german_system() {
    set_lang(Language::German);
    let result = get(StringId::System);
    assert_eq!(result, b"System");
}

#[test]
fn test_get_german_network() {
    set_lang(Language::German);
    let result = get(StringId::Network);
    assert_eq!(result, b"Netzwerk");
}

#[test]
fn test_get_german_privacy() {
    set_lang(Language::German);
    let result = get(StringId::Privacy);
    assert_eq!(result, b"Datenschutz");
}

#[test]
fn test_get_chinese_settings() {
    set_lang(Language::Chinese);
    let result = get(StringId::Settings);
    assert_eq!(result, b"Settings");
}

#[test]
fn test_get_japanese_settings() {
    set_lang(Language::Japanese);
    let result = get(StringId::Settings);
    assert_eq!(result, b"Settings");
}

#[test]
fn test_language_switching() {
    set_lang(Language::English);
    assert_eq!(get(StringId::Cancel), b"Cancel");
    set_lang(Language::Spanish);
    assert_eq!(get(StringId::Cancel), b"Cancelar");
    set_lang(Language::French);
    assert_eq!(get(StringId::Cancel), b"Annuler");
    set_lang(Language::German);
    assert_eq!(get(StringId::Cancel), b"Abbrechen");
}

#[test]
fn test_init_from_settings_callable() {
    init_from_settings();
}
