// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::locale::strings::{StringId, STRINGS_EN, STRINGS_ES, STRINGS_FR, STRINGS_DE, STRINGS_ZH, STRINGS_JA};

#[test]
fn test_string_id_settings() {
    assert_eq!(StringId::Settings as usize, 0);
}

#[test]
fn test_string_id_system() {
    assert_eq!(StringId::System as usize, 1);
}

#[test]
fn test_string_id_network() {
    assert_eq!(StringId::Network as usize, 2);
}

#[test]
fn test_string_id_privacy() {
    assert_eq!(StringId::Privacy as usize, 3);
}

#[test]
fn test_string_id_appearance() {
    assert_eq!(StringId::Appearance as usize, 4);
}

#[test]
fn test_string_id_power() {
    assert_eq!(StringId::Power as usize, 5);
}

#[test]
fn test_string_id_language() {
    assert_eq!(StringId::Language as usize, 6);
}

#[test]
fn test_string_id_timezone() {
    assert_eq!(StringId::Timezone as usize, 7);
}

#[test]
fn test_string_id_theme() {
    assert_eq!(StringId::Theme as usize, 8);
}

#[test]
fn test_string_id_dark() {
    assert_eq!(StringId::Dark as usize, 9);
}

#[test]
fn test_string_id_light() {
    assert_eq!(StringId::Light as usize, 10);
}

#[test]
fn test_string_id_auto() {
    assert_eq!(StringId::Auto as usize, 11);
}

#[test]
fn test_string_id_files() {
    assert_eq!(StringId::Files as usize, 12);
}

#[test]
fn test_string_id_terminal() {
    assert_eq!(StringId::Terminal as usize, 13);
}

#[test]
fn test_string_id_browser() {
    assert_eq!(StringId::Browser as usize, 14);
}

#[test]
fn test_string_id_wallet() {
    assert_eq!(StringId::Wallet as usize, 15);
}

#[test]
fn test_string_id_cancel() {
    assert_eq!(StringId::Cancel as usize, 16);
}

#[test]
fn test_string_id_ok() {
    assert_eq!(StringId::Ok as usize, 17);
}

#[test]
fn test_string_id_apply() {
    assert_eq!(StringId::Apply as usize, 18);
}

#[test]
fn test_string_id_save() {
    assert_eq!(StringId::Save as usize, 19);
}

#[test]
fn test_string_id_delete() {
    assert_eq!(StringId::Delete as usize, 20);
}

#[test]
fn test_string_id_rename() {
    assert_eq!(StringId::Rename as usize, 21);
}

#[test]
fn test_string_id_newfolder() {
    assert_eq!(StringId::NewFolder as usize, 22);
}

#[test]
fn test_string_id_newfile() {
    assert_eq!(StringId::NewFile as usize, 23);
}

#[test]
fn test_string_id_copy() {
    assert_eq!(StringId::Copy as usize, 24);
}

#[test]
fn test_string_id_paste() {
    assert_eq!(StringId::Paste as usize, 25);
}

#[test]
fn test_string_id_cut() {
    assert_eq!(StringId::Cut as usize, 26);
}

#[test]
fn test_string_id_refresh() {
    assert_eq!(StringId::Refresh as usize, 27);
}

#[test]
fn test_string_id_about() {
    assert_eq!(StringId::About as usize, 28);
}

#[test]
fn test_string_id_help() {
    assert_eq!(StringId::Help as usize, 29);
}

#[test]
fn test_string_id_shutdown() {
    assert_eq!(StringId::Shutdown as usize, 30);
}

#[test]
fn test_string_id_restart() {
    assert_eq!(StringId::Restart as usize, 31);
}

#[test]
fn test_string_id_sleep() {
    assert_eq!(StringId::Sleep as usize, 32);
}

#[test]
fn test_string_id_logout() {
    assert_eq!(StringId::Logout as usize, 33);
}

#[test]
fn test_string_id_back() {
    assert_eq!(StringId::Back as usize, 34);
}

#[test]
fn test_string_id_forward() {
    assert_eq!(StringId::Forward as usize, 35);
}

#[test]
fn test_string_id_kernel() {
    assert_eq!(StringId::Kernel as usize, 36);
}

#[test]
fn test_string_id_clone() {
    let id = StringId::Settings;
    let cloned = id.clone();
    assert_eq!(id, cloned);
}

#[test]
fn test_string_id_copy() {
    let id = StringId::System;
    let copied = id;
    assert_eq!(id, copied);
}

#[test]
fn test_string_id_equality() {
    assert_eq!(StringId::Settings, StringId::Settings);
    assert_ne!(StringId::Settings, StringId::System);
}

#[test]
fn test_strings_en_length() {
    assert_eq!(STRINGS_EN.len(), 37);
}

#[test]
fn test_strings_es_length() {
    assert_eq!(STRINGS_ES.len(), 37);
}

#[test]
fn test_strings_fr_length() {
    assert_eq!(STRINGS_FR.len(), 37);
}

#[test]
fn test_strings_de_length() {
    assert_eq!(STRINGS_DE.len(), 37);
}

#[test]
fn test_strings_zh_length() {
    assert_eq!(STRINGS_ZH.len(), 37);
}

#[test]
fn test_strings_ja_length() {
    assert_eq!(STRINGS_JA.len(), 37);
}

#[test]
fn test_strings_en_settings() {
    assert_eq!(STRINGS_EN[StringId::Settings as usize], b"Settings");
}

#[test]
fn test_strings_en_system() {
    assert_eq!(STRINGS_EN[StringId::System as usize], b"System");
}

#[test]
fn test_strings_en_network() {
    assert_eq!(STRINGS_EN[StringId::Network as usize], b"Network");
}

#[test]
fn test_strings_en_privacy() {
    assert_eq!(STRINGS_EN[StringId::Privacy as usize], b"Privacy");
}

#[test]
fn test_strings_en_cancel() {
    assert_eq!(STRINGS_EN[StringId::Cancel as usize], b"Cancel");
}

#[test]
fn test_strings_en_ok() {
    assert_eq!(STRINGS_EN[StringId::Ok as usize], b"OK");
}

#[test]
fn test_strings_en_kernel() {
    assert_eq!(STRINGS_EN[StringId::Kernel as usize], b"Kernel");
}

#[test]
fn test_strings_es_settings() {
    assert_eq!(STRINGS_ES[StringId::Settings as usize], b"Ajustes");
}

#[test]
fn test_strings_es_system() {
    assert_eq!(STRINGS_ES[StringId::System as usize], b"Sistema");
}

#[test]
fn test_strings_es_network() {
    assert_eq!(STRINGS_ES[StringId::Network as usize], b"Red");
}

#[test]
fn test_strings_es_cancel() {
    assert_eq!(STRINGS_ES[StringId::Cancel as usize], b"Cancelar");
}

#[test]
fn test_strings_fr_settings() {
    assert_eq!(STRINGS_FR[StringId::Settings as usize], b"Parametres");
}

#[test]
fn test_strings_fr_system() {
    assert_eq!(STRINGS_FR[StringId::System as usize], b"Systeme");
}

#[test]
fn test_strings_fr_network() {
    assert_eq!(STRINGS_FR[StringId::Network as usize], b"Reseau");
}

#[test]
fn test_strings_fr_cancel() {
    assert_eq!(STRINGS_FR[StringId::Cancel as usize], b"Annuler");
}

#[test]
fn test_strings_de_settings() {
    assert_eq!(STRINGS_DE[StringId::Settings as usize], b"Einstellungen");
}

#[test]
fn test_strings_de_system() {
    assert_eq!(STRINGS_DE[StringId::System as usize], b"System");
}

#[test]
fn test_strings_de_network() {
    assert_eq!(STRINGS_DE[StringId::Network as usize], b"Netzwerk");
}

#[test]
fn test_strings_de_cancel() {
    assert_eq!(STRINGS_DE[StringId::Cancel as usize], b"Abbrechen");
}

#[test]
fn test_all_languages_have_same_string_count() {
    assert_eq!(STRINGS_EN.len(), STRINGS_ES.len());
    assert_eq!(STRINGS_ES.len(), STRINGS_FR.len());
    assert_eq!(STRINGS_FR.len(), STRINGS_DE.len());
    assert_eq!(STRINGS_DE.len(), STRINGS_ZH.len());
    assert_eq!(STRINGS_ZH.len(), STRINGS_JA.len());
}

#[test]
fn test_all_strings_en_non_empty() {
    for s in STRINGS_EN.iter() {
        assert!(!s.is_empty());
    }
}

#[test]
fn test_all_strings_es_non_empty() {
    for s in STRINGS_ES.iter() {
        assert!(!s.is_empty());
    }
}

#[test]
fn test_all_strings_fr_non_empty() {
    for s in STRINGS_FR.iter() {
        assert!(!s.is_empty());
    }
}

#[test]
fn test_all_strings_de_non_empty() {
    for s in STRINGS_DE.iter() {
        assert!(!s.is_empty());
    }
}

#[test]
fn test_string_id_sequential() {
    let ids = [
        StringId::Settings, StringId::System, StringId::Network, StringId::Privacy,
        StringId::Appearance, StringId::Power, StringId::Language, StringId::Timezone,
        StringId::Theme, StringId::Dark, StringId::Light, StringId::Auto,
        StringId::Files, StringId::Terminal, StringId::Browser, StringId::Wallet,
        StringId::Cancel, StringId::Ok, StringId::Apply, StringId::Save,
        StringId::Delete, StringId::Rename, StringId::NewFolder, StringId::NewFile,
        StringId::Copy, StringId::Paste, StringId::Cut, StringId::Refresh,
        StringId::About, StringId::Help, StringId::Shutdown, StringId::Restart,
        StringId::Sleep, StringId::Logout, StringId::Back, StringId::Forward, StringId::Kernel,
    ];
    for (i, id) in ids.iter().enumerate() {
        assert_eq!(*id as usize, i);
    }
}

#[test]
fn test_string_id_max() {
    assert_eq!(StringId::Kernel as usize, 36);
}

#[test]
fn test_strings_valid_utf8() {
    for s in STRINGS_EN.iter() {
        assert!(core::str::from_utf8(s).is_ok());
    }
}

