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
use crate::test::framework::TestResult;

pub(crate) fn test_get_returns_byte_slice() -> TestResult {
    let result = get(StringId::Settings);
    if result.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_settings_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Settings);
    if result != b"Settings" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_system_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::System);
    if result != b"System" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_network_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Network);
    if result != b"Network" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_privacy_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Privacy);
    if result != b"Privacy" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_appearance_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Appearance);
    if result != b"Appearance" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_power_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Power);
    if result != b"Power" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_language_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Language);
    if result != b"Language" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_timezone_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Timezone);
    if result != b"Timezone" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_theme_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Theme);
    if result != b"Theme" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_dark_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Dark);
    if result != b"Dark" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_light_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Light);
    if result != b"Light" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_auto_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Auto);
    if result != b"Auto" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_files_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Files);
    if result != b"Files" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_terminal_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Terminal);
    if result != b"Terminal" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_browser_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Browser);
    if result != b"Browser" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_wallet_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Wallet);
    if result != b"Wallet" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_cancel_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Cancel);
    if result != b"Cancel" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_ok_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Ok);
    if result != b"OK" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_apply_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Apply);
    if result != b"Apply" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_save_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Save);
    if result != b"Save" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_delete_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Delete);
    if result != b"Delete" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_rename_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Rename);
    if result != b"Rename" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_newfolder_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::NewFolder);
    if result != b"New Folder" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_newfile_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::NewFile);
    if result != b"New File" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_copy_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Copy);
    if result != b"Copy" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_paste_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Paste);
    if result != b"Paste" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_cut_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Cut);
    if result != b"Cut" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_refresh_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Refresh);
    if result != b"Refresh" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_about_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::About);
    if result != b"About" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_help_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Help);
    if result != b"Help" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_shutdown_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Shutdown);
    if result != b"Shutdown" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_restart_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Restart);
    if result != b"Restart" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_sleep_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Sleep);
    if result != b"Sleep" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_logout_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Logout);
    if result != b"Logout" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_back_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Back);
    if result != b"Back" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_forward_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Forward);
    if result != b"Forward" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_kernel_string() -> TestResult {
    set_lang(Language::English);
    let result = get(StringId::Kernel);
    if result != b"Kernel" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_lang_returns_language() -> TestResult {
    set_lang(Language::English);
    let lang = get_lang();
    if lang != Language::English {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_lang_english() -> TestResult {
    set_lang(Language::English);
    if get_lang() != Language::English {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_lang_spanish() -> TestResult {
    set_lang(Language::Spanish);
    if get_lang() != Language::Spanish {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_lang_french() -> TestResult {
    set_lang(Language::French);
    if get_lang() != Language::French {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_lang_german() -> TestResult {
    set_lang(Language::German);
    if get_lang() != Language::German {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_lang_chinese() -> TestResult {
    set_lang(Language::Chinese);
    if get_lang() != Language::Chinese {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_lang_japanese() -> TestResult {
    set_lang(Language::Japanese);
    if get_lang() != Language::Japanese {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_spanish_settings() -> TestResult {
    set_lang(Language::Spanish);
    let result = get(StringId::Settings);
    if result != b"Ajustes" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_spanish_system() -> TestResult {
    set_lang(Language::Spanish);
    let result = get(StringId::System);
    if result != b"Sistema" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_spanish_network() -> TestResult {
    set_lang(Language::Spanish);
    let result = get(StringId::Network);
    if result != b"Red" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_spanish_privacy() -> TestResult {
    set_lang(Language::Spanish);
    let result = get(StringId::Privacy);
    if result != b"Privacidad" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_french_settings() -> TestResult {
    set_lang(Language::French);
    let result = get(StringId::Settings);
    if result != b"Parametres" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_french_system() -> TestResult {
    set_lang(Language::French);
    let result = get(StringId::System);
    if result != b"Systeme" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_french_network() -> TestResult {
    set_lang(Language::French);
    let result = get(StringId::Network);
    if result != b"Reseau" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_french_privacy() -> TestResult {
    set_lang(Language::French);
    let result = get(StringId::Privacy);
    if result != b"Confidentialite" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_german_settings() -> TestResult {
    set_lang(Language::German);
    let result = get(StringId::Settings);
    if result != b"Einstellungen" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_german_system() -> TestResult {
    set_lang(Language::German);
    let result = get(StringId::System);
    if result != b"System" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_german_network() -> TestResult {
    set_lang(Language::German);
    let result = get(StringId::Network);
    if result != b"Netzwerk" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_german_privacy() -> TestResult {
    set_lang(Language::German);
    let result = get(StringId::Privacy);
    if result != b"Datenschutz" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_chinese_settings() -> TestResult {
    set_lang(Language::Chinese);
    let result = get(StringId::Settings);
    if result != b"Settings" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_japanese_settings() -> TestResult {
    set_lang(Language::Japanese);
    let result = get(StringId::Settings);
    if result != b"Settings" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_switching() -> TestResult {
    set_lang(Language::English);
    if get(StringId::Cancel) != b"Cancel" {
        return TestResult::Fail;
    }
    set_lang(Language::Spanish);
    if get(StringId::Cancel) != b"Cancelar" {
        return TestResult::Fail;
    }
    set_lang(Language::French);
    if get(StringId::Cancel) != b"Annuler" {
        return TestResult::Fail;
    }
    set_lang(Language::German);
    if get(StringId::Cancel) != b"Abbrechen" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_init_from_settings_callable() -> TestResult {
    init_from_settings();
    TestResult::Pass
}
