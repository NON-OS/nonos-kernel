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

use super::strings::{
    StringId, STRINGS_DE, STRINGS_EN, STRINGS_ES, STRINGS_FR, STRINGS_JA, STRINGS_ZH,
};
use core::sync::atomic::{AtomicU8, Ordering};

static CURRENT_LANG: AtomicU8 = AtomicU8::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Language {
    English = 0,
    Spanish = 1,
    French = 2,
    German = 3,
    Chinese = 4,
    Japanese = 5,
}

impl From<u8> for Language {
    fn from(v: u8) -> Self {
        match v {
            1 => Language::Spanish,
            2 => Language::French,
            3 => Language::German,
            4 => Language::Chinese,
            5 => Language::Japanese,
            _ => Language::English,
        }
    }
}

pub fn get_lang() -> Language {
    Language::from(CURRENT_LANG.load(Ordering::Relaxed))
}

pub fn set_lang(lang: Language) {
    CURRENT_LANG.store(lang as u8, Ordering::SeqCst);
    crate::sys::settings::set_language(lang as u8);
}

pub fn get(id: StringId) -> &'static [u8] {
    let strings = match get_lang() {
        Language::English => &STRINGS_EN,
        Language::Spanish => &STRINGS_ES,
        Language::French => &STRINGS_FR,
        Language::German => &STRINGS_DE,
        Language::Chinese => &STRINGS_ZH,
        Language::Japanese => &STRINGS_JA,
    };
    strings.get(id as usize).copied().unwrap_or(b"???")
}

pub fn init_from_settings() {
    let lang = crate::sys::settings::language();
    CURRENT_LANG.store(lang, Ordering::SeqCst);
}
