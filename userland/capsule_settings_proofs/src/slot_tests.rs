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

//! The rows the Settings cursor stops on in Appearance: the theme and high
//! contrast, the desktop's wallpaper, the count of those kept, then every
//! wallpaper of the collection in catalog order, then the pointer. A wallpaper row is a stop of
//! its own and names no field, so nothing meant for a field acts on it.

use nonos_policy_proto::wallpaper_labels::WALLPAPER_LABELS;
use nonos_policy_proto::Field;

use crate::settings::schema::{field_at, field_count, slot_at, Slot};
use crate::settings::section::Section;

#[test]
fn appearance_stops_on_every_wallpaper_in_order() {
    let n = WALLPAPER_LABELS.len();
    let s = Section::Appearance;
    assert_eq!(field_count(s), 4 + n + 1);
    assert!(slot_at(s, 0) == Some(Slot::Field(Field::Theme)));
    assert!(slot_at(s, 1) == Some(Slot::Field(Field::HighContrast)));
    assert!(slot_at(s, 2) == Some(Slot::Field(Field::Wallpaper)));
    assert!(slot_at(s, 3) == Some(Slot::Field(Field::WallpapersKept)));
    for i in 0..n {
        assert!(slot_at(s, 4 + i) == Some(Slot::Wallpaper(i as u8)), "wallpaper {i}");
        assert!(field_at(s, 4 + i).is_none(), "a wallpaper row names no field");
    }
    assert!(slot_at(s, 4 + n) == Some(Slot::Field(Field::MouseSensitivity)));
    assert!(slot_at(s, 5 + n).is_none());
}

#[test]
fn a_section_without_the_list_counts_its_fields_alone() {
    let s = Section::Sound;
    for i in 0..field_count(s) {
        assert!(matches!(slot_at(s, i), Some(Slot::Field(_))));
    }
}
