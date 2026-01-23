// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

#[cfg(test)]
mod tests {
    use super::layout::{get_ascii_mapping, Layout};

    #[test]
    fn test_us_qwerty_mapping() {
        let map = get_ascii_mapping(Layout::UsQwerty);
        assert_eq!(map[2], b'1');
        assert_eq!(map[16], b'q');
        assert_eq!(map[30], b'a');
        assert_eq!(map[57], b' ');
    }

    #[test]
    fn test_dvorak_mapping() {
        let map = get_ascii_mapping(Layout::Dvorak);
        assert_eq!(map[16], b'\'');
        assert_eq!(map[30], b'a');
        assert_eq!(map[18], b',');
    }

    #[test]
    fn test_azerty_mapping() {
        let map = get_ascii_mapping(Layout::Azerty);
        assert_eq!(map[2], b'&');
        assert_eq!(map[16], b'a');
        assert_eq!(map[44], b'!');
    }

    #[test]
    fn test_colemak_mapping() {
        let map = get_ascii_mapping(Layout::Colemak);
        assert_eq!(map[2], b'1');
        assert_eq!(map[30], b'a');
        assert_eq!(map[18], b'f');
    }
}
