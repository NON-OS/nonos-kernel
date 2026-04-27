// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::locale::strings::{
    StringId, STRINGS_DE, STRINGS_EN, STRINGS_ES, STRINGS_FR, STRINGS_JA, STRINGS_ZH,
};
use crate::test::framework::TestResult;

pub(crate) fn test_string_id_settings() -> TestResult {
    if StringId::Settings as usize != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_system() -> TestResult {
    if StringId::System as usize != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_network() -> TestResult {
    if StringId::Network as usize != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_privacy() -> TestResult {
    if StringId::Privacy as usize != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_appearance() -> TestResult {
    if StringId::Appearance as usize != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_power() -> TestResult {
    if StringId::Power as usize != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_language() -> TestResult {
    if StringId::Language as usize != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_timezone() -> TestResult {
    if StringId::Timezone as usize != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_theme() -> TestResult {
    if StringId::Theme as usize != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_dark() -> TestResult {
    if StringId::Dark as usize != 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_light() -> TestResult {
    if StringId::Light as usize != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_auto() -> TestResult {
    if StringId::Auto as usize != 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_files() -> TestResult {
    if StringId::Files as usize != 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_terminal() -> TestResult {
    if StringId::Terminal as usize != 13 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_browser() -> TestResult {
    if StringId::Browser as usize != 14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_wallet() -> TestResult {
    if StringId::Wallet as usize != 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_cancel() -> TestResult {
    if StringId::Cancel as usize != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_ok() -> TestResult {
    if StringId::Ok as usize != 17 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_apply() -> TestResult {
    if StringId::Apply as usize != 18 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_save() -> TestResult {
    if StringId::Save as usize != 19 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_delete() -> TestResult {
    if StringId::Delete as usize != 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_rename() -> TestResult {
    if StringId::Rename as usize != 21 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_newfolder() -> TestResult {
    if StringId::NewFolder as usize != 22 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_newfile() -> TestResult {
    if StringId::NewFile as usize != 23 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_copy() -> TestResult {
    if StringId::Copy as usize != 24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_paste() -> TestResult {
    if StringId::Paste as usize != 25 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_cut() -> TestResult {
    if StringId::Cut as usize != 26 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_refresh() -> TestResult {
    if StringId::Refresh as usize != 27 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_about() -> TestResult {
    if StringId::About as usize != 28 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_help() -> TestResult {
    if StringId::Help as usize != 29 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_shutdown() -> TestResult {
    if StringId::Shutdown as usize != 30 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_restart() -> TestResult {
    if StringId::Restart as usize != 31 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_sleep() -> TestResult {
    if StringId::Sleep as usize != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_logout() -> TestResult {
    if StringId::Logout as usize != 33 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_back() -> TestResult {
    if StringId::Back as usize != 34 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_forward() -> TestResult {
    if StringId::Forward as usize != 35 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_kernel() -> TestResult {
    if StringId::Kernel as usize != 36 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_clone() -> TestResult {
    let id = StringId::Settings;
    let cloned = id.clone();
    if id != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_copy_trait() -> TestResult {
    let id = StringId::System;
    let copied = id;
    if id != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_equality() -> TestResult {
    if StringId::Settings != StringId::Settings {
        return TestResult::Fail;
    }
    if StringId::Settings == StringId::System {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_en_length() -> TestResult {
    if STRINGS_EN.len() != 37 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_es_length() -> TestResult {
    if STRINGS_ES.len() != 37 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_fr_length() -> TestResult {
    if STRINGS_FR.len() != 37 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_de_length() -> TestResult {
    if STRINGS_DE.len() != 37 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_zh_length() -> TestResult {
    if STRINGS_ZH.len() != 37 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_ja_length() -> TestResult {
    if STRINGS_JA.len() != 37 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_en_settings() -> TestResult {
    if STRINGS_EN[StringId::Settings as usize] != b"Settings" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_en_system() -> TestResult {
    if STRINGS_EN[StringId::System as usize] != b"System" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_en_network() -> TestResult {
    if STRINGS_EN[StringId::Network as usize] != b"Network" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_en_privacy() -> TestResult {
    if STRINGS_EN[StringId::Privacy as usize] != b"Privacy" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_en_cancel() -> TestResult {
    if STRINGS_EN[StringId::Cancel as usize] != b"Cancel" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_en_ok() -> TestResult {
    if STRINGS_EN[StringId::Ok as usize] != b"OK" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_en_kernel() -> TestResult {
    if STRINGS_EN[StringId::Kernel as usize] != b"Kernel" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_es_settings() -> TestResult {
    if STRINGS_ES[StringId::Settings as usize] != b"Ajustes" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_es_system() -> TestResult {
    if STRINGS_ES[StringId::System as usize] != b"Sistema" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_es_network() -> TestResult {
    if STRINGS_ES[StringId::Network as usize] != b"Red" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_es_cancel() -> TestResult {
    if STRINGS_ES[StringId::Cancel as usize] != b"Cancelar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_fr_settings() -> TestResult {
    if STRINGS_FR[StringId::Settings as usize] != b"Parametres" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_fr_system() -> TestResult {
    if STRINGS_FR[StringId::System as usize] != b"Systeme" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_fr_network() -> TestResult {
    if STRINGS_FR[StringId::Network as usize] != b"Reseau" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_fr_cancel() -> TestResult {
    if STRINGS_FR[StringId::Cancel as usize] != b"Annuler" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_de_settings() -> TestResult {
    if STRINGS_DE[StringId::Settings as usize] != b"Einstellungen" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_de_system() -> TestResult {
    if STRINGS_DE[StringId::System as usize] != b"System" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_de_network() -> TestResult {
    if STRINGS_DE[StringId::Network as usize] != b"Netzwerk" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_de_cancel() -> TestResult {
    if STRINGS_DE[StringId::Cancel as usize] != b"Abbrechen" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_languages_have_same_string_count() -> TestResult {
    if STRINGS_EN.len() != STRINGS_ES.len() {
        return TestResult::Fail;
    }
    if STRINGS_ES.len() != STRINGS_FR.len() {
        return TestResult::Fail;
    }
    if STRINGS_FR.len() != STRINGS_DE.len() {
        return TestResult::Fail;
    }
    if STRINGS_DE.len() != STRINGS_ZH.len() {
        return TestResult::Fail;
    }
    if STRINGS_ZH.len() != STRINGS_JA.len() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_strings_en_non_empty() -> TestResult {
    for s in STRINGS_EN.iter() {
        if s.is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_all_strings_es_non_empty() -> TestResult {
    for s in STRINGS_ES.iter() {
        if s.is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_all_strings_fr_non_empty() -> TestResult {
    for s in STRINGS_FR.iter() {
        if s.is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_all_strings_de_non_empty() -> TestResult {
    for s in STRINGS_DE.iter() {
        if s.is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_sequential() -> TestResult {
    let ids = [
        StringId::Settings,
        StringId::System,
        StringId::Network,
        StringId::Privacy,
        StringId::Appearance,
        StringId::Power,
        StringId::Language,
        StringId::Timezone,
        StringId::Theme,
        StringId::Dark,
        StringId::Light,
        StringId::Auto,
        StringId::Files,
        StringId::Terminal,
        StringId::Browser,
        StringId::Wallet,
        StringId::Cancel,
        StringId::Ok,
        StringId::Apply,
        StringId::Save,
        StringId::Delete,
        StringId::Rename,
        StringId::NewFolder,
        StringId::NewFile,
        StringId::Copy,
        StringId::Paste,
        StringId::Cut,
        StringId::Refresh,
        StringId::About,
        StringId::Help,
        StringId::Shutdown,
        StringId::Restart,
        StringId::Sleep,
        StringId::Logout,
        StringId::Back,
        StringId::Forward,
        StringId::Kernel,
    ];
    for (i, id) in ids.iter().enumerate() {
        if *id as usize != i {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_string_id_max() -> TestResult {
    if StringId::Kernel as usize != 36 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_strings_valid_utf8() -> TestResult {
    for s in STRINGS_EN.iter() {
        if core::str::from_utf8(s).is_err() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
