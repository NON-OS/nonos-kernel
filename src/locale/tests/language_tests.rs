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

pub(crate) fn test_language_english_value() -> TestResult {
    if Language::English as u8 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_spanish_value() -> TestResult {
    if Language::Spanish as u8 != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_french_value() -> TestResult {
    if Language::French as u8 != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_german_value() -> TestResult {
    if Language::German as u8 != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_chinese_value() -> TestResult {
    if Language::Chinese as u8 != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_japanese_value() -> TestResult {
    if Language::Japanese as u8 != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_from_0() -> TestResult {
    let lang: Language = Language::from(0);
    if lang != Language::English {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_from_1() -> TestResult {
    let lang: Language = Language::from(1);
    if lang != Language::Spanish {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_from_2() -> TestResult {
    let lang: Language = Language::from(2);
    if lang != Language::French {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_from_3() -> TestResult {
    let lang: Language = Language::from(3);
    if lang != Language::German {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_from_4() -> TestResult {
    let lang: Language = Language::from(4);
    if lang != Language::Chinese {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_from_5() -> TestResult {
    let lang: Language = Language::from(5);
    if lang != Language::Japanese {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_from_invalid_defaults_english() -> TestResult {
    let lang: Language = Language::from(6);
    if lang != Language::English {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_from_large_value_defaults_english() -> TestResult {
    let lang: Language = Language::from(255);
    if lang != Language::English {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_from_100_defaults_english() -> TestResult {
    let lang: Language = Language::from(100);
    if lang != Language::English {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_clone() -> TestResult {
    let lang1 = Language::Spanish;
    let lang2 = lang1.clone();
    if lang1 != lang2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_copy() -> TestResult {
    let lang1 = Language::French;
    let lang2 = lang1;
    if lang1 != lang2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_eq_same() -> TestResult {
    if Language::German != Language::German {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_eq_different() -> TestResult {
    if Language::Chinese == Language::Japanese {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_partial_eq() -> TestResult {
    let lang1 = Language::English;
    let lang2 = Language::English;
    if !(lang1 == lang2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_not_eq() -> TestResult {
    let lang1 = Language::English;
    let lang2 = Language::Spanish;
    if !(lang1 != lang2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_repr_u8() -> TestResult {
    if core::mem::size_of::<Language>() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_and_get_lang_english() -> TestResult {
    set_lang(Language::English);
    if get_lang() != Language::English {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_and_get_lang_spanish() -> TestResult {
    set_lang(Language::Spanish);
    if get_lang() != Language::Spanish {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_and_get_lang_french() -> TestResult {
    set_lang(Language::French);
    if get_lang() != Language::French {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_and_get_lang_german() -> TestResult {
    set_lang(Language::German);
    if get_lang() != Language::German {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_and_get_lang_chinese() -> TestResult {
    set_lang(Language::Chinese);
    if get_lang() != Language::Chinese {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_and_get_lang_japanese() -> TestResult {
    set_lang(Language::Japanese);
    if get_lang() != Language::Japanese {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_switch_affects_strings() -> TestResult {
    set_lang(Language::English);
    let en = get(StringId::Settings);
    set_lang(Language::Spanish);
    let es = get(StringId::Settings);
    if en == es {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_roundtrip_english() -> TestResult {
    set_lang(Language::English);
    let val = get_lang() as u8;
    let lang = Language::from(val);
    if lang != Language::English {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_roundtrip_spanish() -> TestResult {
    set_lang(Language::Spanish);
    let val = get_lang() as u8;
    let lang = Language::from(val);
    if lang != Language::Spanish {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_roundtrip_french() -> TestResult {
    set_lang(Language::French);
    let val = get_lang() as u8;
    let lang = Language::from(val);
    if lang != Language::French {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_roundtrip_german() -> TestResult {
    set_lang(Language::German);
    let val = get_lang() as u8;
    let lang = Language::from(val);
    if lang != Language::German {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_roundtrip_chinese() -> TestResult {
    set_lang(Language::Chinese);
    let val = get_lang() as u8;
    let lang = Language::from(val);
    if lang != Language::Chinese {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_roundtrip_japanese() -> TestResult {
    set_lang(Language::Japanese);
    let val = get_lang() as u8;
    let lang = Language::from(val);
    if lang != Language::Japanese {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiple_language_switches() -> TestResult {
    set_lang(Language::English);
    if get_lang() != Language::English {
        return TestResult::Fail;
    }
    set_lang(Language::Spanish);
    if get_lang() != Language::Spanish {
        return TestResult::Fail;
    }
    set_lang(Language::French);
    if get_lang() != Language::French {
        return TestResult::Fail;
    }
    set_lang(Language::German);
    if get_lang() != Language::German {
        return TestResult::Fail;
    }
    set_lang(Language::Chinese);
    if get_lang() != Language::Chinese {
        return TestResult::Fail;
    }
    set_lang(Language::Japanese);
    if get_lang() != Language::Japanese {
        return TestResult::Fail;
    }
    set_lang(Language::English);
    if get_lang() != Language::English {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_language_all_variants_accessible() -> TestResult {
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
        if get_lang() != lang {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_language_from_all_valid_values() -> TestResult {
    let expected = [
        Language::English,
        Language::Spanish,
        Language::French,
        Language::German,
        Language::Chinese,
        Language::Japanese,
    ];
    for (i, exp) in expected.iter().enumerate() {
        if Language::from(i as u8) != *exp {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_spanish_ok_string() -> TestResult {
    set_lang(Language::Spanish);
    if get(StringId::Ok) != b"Aceptar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_spanish_save_string() -> TestResult {
    set_lang(Language::Spanish);
    if get(StringId::Save) != b"Guardar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_spanish_delete_string() -> TestResult {
    set_lang(Language::Spanish);
    if get(StringId::Delete) != b"Eliminar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_spanish_copy_string() -> TestResult {
    set_lang(Language::Spanish);
    if get(StringId::Copy) != b"Copiar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_spanish_paste_string() -> TestResult {
    set_lang(Language::Spanish);
    if get(StringId::Paste) != b"Pegar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_french_ok_string() -> TestResult {
    set_lang(Language::French);
    if get(StringId::Ok) != b"OK" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_french_save_string() -> TestResult {
    set_lang(Language::French);
    if get(StringId::Save) != b"Enregistrer" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_french_delete_string() -> TestResult {
    set_lang(Language::French);
    if get(StringId::Delete) != b"Supprimer" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_french_copy_string() -> TestResult {
    set_lang(Language::French);
    if get(StringId::Copy) != b"Copier" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_french_paste_string() -> TestResult {
    set_lang(Language::French);
    if get(StringId::Paste) != b"Coller" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_german_ok_string() -> TestResult {
    set_lang(Language::German);
    if get(StringId::Ok) != b"OK" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_german_save_string() -> TestResult {
    set_lang(Language::German);
    if get(StringId::Save) != b"Speichern" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_german_delete_string() -> TestResult {
    set_lang(Language::German);
    if get(StringId::Delete) != b"Loschen" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_german_copy_string() -> TestResult {
    set_lang(Language::German);
    if get(StringId::Copy) != b"Kopieren" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_german_paste_string() -> TestResult {
    set_lang(Language::German);
    if get(StringId::Paste) != b"Einfugen" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_spanish_shutdown_string() -> TestResult {
    set_lang(Language::Spanish);
    if get(StringId::Shutdown) != b"Apagar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_spanish_restart_string() -> TestResult {
    set_lang(Language::Spanish);
    if get(StringId::Restart) != b"Reiniciar" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_french_shutdown_string() -> TestResult {
    set_lang(Language::French);
    if get(StringId::Shutdown) != b"Eteindre" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_french_restart_string() -> TestResult {
    set_lang(Language::French);
    if get(StringId::Restart) != b"Redemarrer" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_german_shutdown_string() -> TestResult {
    set_lang(Language::German);
    if get(StringId::Shutdown) != b"Herunterfahren" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_german_restart_string() -> TestResult {
    set_lang(Language::German);
    if get(StringId::Restart) != b"Neustart" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_spanish_appearance_string() -> TestResult {
    set_lang(Language::Spanish);
    if get(StringId::Appearance) != b"Apariencia" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_french_appearance_string() -> TestResult {
    set_lang(Language::French);
    if get(StringId::Appearance) != b"Apparence" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_german_appearance_string() -> TestResult {
    set_lang(Language::German);
    if get(StringId::Appearance) != b"Erscheinung" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_spanish_power_string() -> TestResult {
    set_lang(Language::Spanish);
    if get(StringId::Power) != b"Energia" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_french_power_string() -> TestResult {
    set_lang(Language::French);
    if get(StringId::Power) != b"Alimentation" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_german_power_string() -> TestResult {
    set_lang(Language::German);
    if get(StringId::Power) != b"Energie" {
        return TestResult::Fail;
    }
    TestResult::Pass
}
