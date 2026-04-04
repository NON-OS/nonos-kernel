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
fn test_language_english_value() {
    assert_eq!(Language::English as u8, 0);
}

#[test]
fn test_language_spanish_value() {
    assert_eq!(Language::Spanish as u8, 1);
}

#[test]
fn test_language_french_value() {
    assert_eq!(Language::French as u8, 2);
}

#[test]
fn test_language_german_value() {
    assert_eq!(Language::German as u8, 3);
}

#[test]
fn test_language_chinese_value() {
    assert_eq!(Language::Chinese as u8, 4);
}

#[test]
fn test_language_japanese_value() {
    assert_eq!(Language::Japanese as u8, 5);
}

#[test]
fn test_language_from_0() {
    let lang: Language = Language::from(0);
    assert_eq!(lang, Language::English);
}

#[test]
fn test_language_from_1() {
    let lang: Language = Language::from(1);
    assert_eq!(lang, Language::Spanish);
}

#[test]
fn test_language_from_2() {
    let lang: Language = Language::from(2);
    assert_eq!(lang, Language::French);
}

#[test]
fn test_language_from_3() {
    let lang: Language = Language::from(3);
    assert_eq!(lang, Language::German);
}

#[test]
fn test_language_from_4() {
    let lang: Language = Language::from(4);
    assert_eq!(lang, Language::Chinese);
}

#[test]
fn test_language_from_5() {
    let lang: Language = Language::from(5);
    assert_eq!(lang, Language::Japanese);
}

#[test]
fn test_language_from_invalid_defaults_english() {
    let lang: Language = Language::from(6);
    assert_eq!(lang, Language::English);
}

#[test]
fn test_language_from_large_value_defaults_english() {
    let lang: Language = Language::from(255);
    assert_eq!(lang, Language::English);
}

#[test]
fn test_language_from_100_defaults_english() {
    let lang: Language = Language::from(100);
    assert_eq!(lang, Language::English);
}

#[test]
fn test_language_clone() {
    let lang1 = Language::Spanish;
    let lang2 = lang1.clone();
    assert_eq!(lang1, lang2);
}

#[test]
fn test_language_copy() {
    let lang1 = Language::French;
    let lang2 = lang1;
    assert_eq!(lang1, lang2);
}

#[test]
fn test_language_eq_same() {
    assert_eq!(Language::German, Language::German);
}

#[test]
fn test_language_eq_different() {
    assert_ne!(Language::Chinese, Language::Japanese);
}

#[test]
fn test_language_partial_eq() {
    let lang1 = Language::English;
    let lang2 = Language::English;
    assert!(lang1 == lang2);
}

#[test]
fn test_language_not_eq() {
    let lang1 = Language::English;
    let lang2 = Language::Spanish;
    assert!(lang1 != lang2);
}

#[test]
fn test_language_repr_u8() {
    assert_eq!(core::mem::size_of::<Language>(), 1);
}

#[test]
fn test_set_and_get_lang_english() {
    set_lang(Language::English);
    assert_eq!(get_lang(), Language::English);
}

#[test]
fn test_set_and_get_lang_spanish() {
    set_lang(Language::Spanish);
    assert_eq!(get_lang(), Language::Spanish);
}

#[test]
fn test_set_and_get_lang_french() {
    set_lang(Language::French);
    assert_eq!(get_lang(), Language::French);
}

#[test]
fn test_set_and_get_lang_german() {
    set_lang(Language::German);
    assert_eq!(get_lang(), Language::German);
}

#[test]
fn test_set_and_get_lang_chinese() {
    set_lang(Language::Chinese);
    assert_eq!(get_lang(), Language::Chinese);
}

#[test]
fn test_set_and_get_lang_japanese() {
    set_lang(Language::Japanese);
    assert_eq!(get_lang(), Language::Japanese);
}

#[test]
fn test_language_switch_affects_strings() {
    set_lang(Language::English);
    let en = get(StringId::Settings);
    set_lang(Language::Spanish);
    let es = get(StringId::Settings);
    assert_ne!(en, es);
}

#[test]
fn test_language_roundtrip_english() {
    set_lang(Language::English);
    let val = get_lang() as u8;
    let lang = Language::from(val);
    assert_eq!(lang, Language::English);
}

#[test]
fn test_language_roundtrip_spanish() {
    set_lang(Language::Spanish);
    let val = get_lang() as u8;
    let lang = Language::from(val);
    assert_eq!(lang, Language::Spanish);
}

#[test]
fn test_language_roundtrip_french() {
    set_lang(Language::French);
    let val = get_lang() as u8;
    let lang = Language::from(val);
    assert_eq!(lang, Language::French);
}

#[test]
fn test_language_roundtrip_german() {
    set_lang(Language::German);
    let val = get_lang() as u8;
    let lang = Language::from(val);
    assert_eq!(lang, Language::German);
}

#[test]
fn test_language_roundtrip_chinese() {
    set_lang(Language::Chinese);
    let val = get_lang() as u8;
    let lang = Language::from(val);
    assert_eq!(lang, Language::Chinese);
}

#[test]
fn test_language_roundtrip_japanese() {
    set_lang(Language::Japanese);
    let val = get_lang() as u8;
    let lang = Language::from(val);
    assert_eq!(lang, Language::Japanese);
}

#[test]
fn test_multiple_language_switches() {
    set_lang(Language::English);
    assert_eq!(get_lang(), Language::English);
    set_lang(Language::Spanish);
    assert_eq!(get_lang(), Language::Spanish);
    set_lang(Language::French);
    assert_eq!(get_lang(), Language::French);
    set_lang(Language::German);
    assert_eq!(get_lang(), Language::German);
    set_lang(Language::Chinese);
    assert_eq!(get_lang(), Language::Chinese);
    set_lang(Language::Japanese);
    assert_eq!(get_lang(), Language::Japanese);
    set_lang(Language::English);
    assert_eq!(get_lang(), Language::English);
}

#[test]
fn test_language_all_variants_accessible() {
    let languages = [
        Language::English,
        Language::Spanish,
        Language::French,
        Language::German,
        Language::Chinese,
        Language::Japanese,
    ];
    for lang in languages {
        set_lang(lang);
        assert_eq!(get_lang(), lang);
    }
}

#[test]
fn test_language_from_all_valid_values() {
    let expected = [
        Language::English,
        Language::Spanish,
        Language::French,
        Language::German,
        Language::Chinese,
        Language::Japanese,
    ];
    for (i, exp) in expected.iter().enumerate() {
        assert_eq!(Language::from(i as u8), *exp);
    }
}

#[test]
fn test_spanish_ok_string() {
    set_lang(Language::Spanish);
    assert_eq!(get(StringId::Ok), b"Aceptar");
}

#[test]
fn test_spanish_save_string() {
    set_lang(Language::Spanish);
    assert_eq!(get(StringId::Save), b"Guardar");
}

#[test]
fn test_spanish_delete_string() {
    set_lang(Language::Spanish);
    assert_eq!(get(StringId::Delete), b"Eliminar");
}

#[test]
fn test_spanish_copy_string() {
    set_lang(Language::Spanish);
    assert_eq!(get(StringId::Copy), b"Copiar");
}

#[test]
fn test_spanish_paste_string() {
    set_lang(Language::Spanish);
    assert_eq!(get(StringId::Paste), b"Pegar");
}

#[test]
fn test_french_ok_string() {
    set_lang(Language::French);
    assert_eq!(get(StringId::Ok), b"OK");
}

#[test]
fn test_french_save_string() {
    set_lang(Language::French);
    assert_eq!(get(StringId::Save), b"Enregistrer");
}

#[test]
fn test_french_delete_string() {
    set_lang(Language::French);
    assert_eq!(get(StringId::Delete), b"Supprimer");
}

#[test]
fn test_french_copy_string() {
    set_lang(Language::French);
    assert_eq!(get(StringId::Copy), b"Copier");
}

#[test]
fn test_french_paste_string() {
    set_lang(Language::French);
    assert_eq!(get(StringId::Paste), b"Coller");
}

#[test]
fn test_german_ok_string() {
    set_lang(Language::German);
    assert_eq!(get(StringId::Ok), b"OK");
}

#[test]
fn test_german_save_string() {
    set_lang(Language::German);
    assert_eq!(get(StringId::Save), b"Speichern");
}

#[test]
fn test_german_delete_string() {
    set_lang(Language::German);
    assert_eq!(get(StringId::Delete), b"Loschen");
}

#[test]
fn test_german_copy_string() {
    set_lang(Language::German);
    assert_eq!(get(StringId::Copy), b"Kopieren");
}

#[test]
fn test_german_paste_string() {
    set_lang(Language::German);
    assert_eq!(get(StringId::Paste), b"Einfugen");
}

#[test]
fn test_spanish_shutdown_string() {
    set_lang(Language::Spanish);
    assert_eq!(get(StringId::Shutdown), b"Apagar");
}

#[test]
fn test_spanish_restart_string() {
    set_lang(Language::Spanish);
    assert_eq!(get(StringId::Restart), b"Reiniciar");
}

#[test]
fn test_french_shutdown_string() {
    set_lang(Language::French);
    assert_eq!(get(StringId::Shutdown), b"Eteindre");
}

#[test]
fn test_french_restart_string() {
    set_lang(Language::French);
    assert_eq!(get(StringId::Restart), b"Redemarrer");
}

#[test]
fn test_german_shutdown_string() {
    set_lang(Language::German);
    assert_eq!(get(StringId::Shutdown), b"Herunterfahren");
}

#[test]
fn test_german_restart_string() {
    set_lang(Language::German);
    assert_eq!(get(StringId::Restart), b"Neustart");
}

#[test]
fn test_spanish_appearance_string() {
    set_lang(Language::Spanish);
    assert_eq!(get(StringId::Appearance), b"Apariencia");
}

#[test]
fn test_french_appearance_string() {
    set_lang(Language::French);
    assert_eq!(get(StringId::Appearance), b"Apparence");
}

#[test]
fn test_german_appearance_string() {
    set_lang(Language::German);
    assert_eq!(get(StringId::Appearance), b"Erscheinung");
}

#[test]
fn test_spanish_power_string() {
    set_lang(Language::Spanish);
    assert_eq!(get(StringId::Power), b"Energia");
}

#[test]
fn test_french_power_string() {
    set_lang(Language::French);
    assert_eq!(get(StringId::Power), b"Alimentation");
}

#[test]
fn test_german_power_string() {
    set_lang(Language::German);
    assert_eq!(get(StringId::Power), b"Energie");
}
