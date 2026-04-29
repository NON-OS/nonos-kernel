// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

pub(super) static SCALE_OPTIONS: &[(u8, &str)] = &[
    (100, "100%"),
    (125, "125%"),
    (150, "150%"),
    (175, "175%"),
    (200, "200%"),
];

pub(super) fn scale_label(scale: u8) -> &'static str {
    SCALE_OPTIONS
        .iter()
        .find(|(s, _)| *s == scale)
        .map(|(_, l)| *l)
        .unwrap_or("100%")
}

pub(super) fn scale_index(scale: u8) -> usize {
    SCALE_OPTIONS
        .iter()
        .position(|(s, _)| *s == scale)
        .unwrap_or(0)
}

pub(super) fn scale_from_index(idx: usize) -> u8 {
    SCALE_OPTIONS.get(idx).map(|(s, _)| *s).unwrap_or(100)
}

pub(super) fn scale_count() -> usize {
    SCALE_OPTIONS.len()
}
