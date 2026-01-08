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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyEvent {
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Insert,
    Delete,
    Escape,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
}

impl KeyEvent {
    #[inline]
    pub fn to_code(&self) -> u8 {
        match self {
            KeyEvent::Up => 1,
            KeyEvent::Down => 2,
            KeyEvent::Left => 3,
            KeyEvent::Right => 4,
            KeyEvent::Home => 5,
            KeyEvent::End => 6,
            KeyEvent::PageUp => 7,
            KeyEvent::PageDown => 8,
            KeyEvent::Insert => 9,
            KeyEvent::Delete => 10,
            KeyEvent::Escape => 11,
            KeyEvent::F1 => 12,
            KeyEvent::F2 => 13,
            KeyEvent::F3 => 14,
            KeyEvent::F4 => 15,
            KeyEvent::F5 => 16,
            KeyEvent::F6 => 17,
            KeyEvent::F7 => 18,
            KeyEvent::F8 => 19,
            KeyEvent::F9 => 20,
            KeyEvent::F10 => 21,
            KeyEvent::F11 => 22,
            KeyEvent::F12 => 23,
        }
    }

    #[inline]
    pub fn from_code(code: u8) -> Option<KeyEvent> {
        match code {
            1 => Some(KeyEvent::Up),
            2 => Some(KeyEvent::Down),
            3 => Some(KeyEvent::Left),
            4 => Some(KeyEvent::Right),
            5 => Some(KeyEvent::Home),
            6 => Some(KeyEvent::End),
            7 => Some(KeyEvent::PageUp),
            8 => Some(KeyEvent::PageDown),
            9 => Some(KeyEvent::Insert),
            10 => Some(KeyEvent::Delete),
            11 => Some(KeyEvent::Escape),
            12 => Some(KeyEvent::F1),
            13 => Some(KeyEvent::F2),
            14 => Some(KeyEvent::F3),
            15 => Some(KeyEvent::F4),
            16 => Some(KeyEvent::F5),
            17 => Some(KeyEvent::F6),
            18 => Some(KeyEvent::F7),
            19 => Some(KeyEvent::F8),
            20 => Some(KeyEvent::F9),
            21 => Some(KeyEvent::F10),
            22 => Some(KeyEvent::F11),
            23 => Some(KeyEvent::F12),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            KeyEvent::Up => "Up",
            KeyEvent::Down => "Down",
            KeyEvent::Left => "Left",
            KeyEvent::Right => "Right",
            KeyEvent::Home => "Home",
            KeyEvent::End => "End",
            KeyEvent::PageUp => "PageUp",
            KeyEvent::PageDown => "PageDown",
            KeyEvent::Insert => "Insert",
            KeyEvent::Delete => "Delete",
            KeyEvent::Escape => "Escape",
            KeyEvent::F1 => "F1",
            KeyEvent::F2 => "F2",
            KeyEvent::F3 => "F3",
            KeyEvent::F4 => "F4",
            KeyEvent::F5 => "F5",
            KeyEvent::F6 => "F6",
            KeyEvent::F7 => "F7",
            KeyEvent::F8 => "F8",
            KeyEvent::F9 => "F9",
            KeyEvent::F10 => "F10",
            KeyEvent::F11 => "F11",
            KeyEvent::F12 => "F12",
        }
    }

    #[inline]
    pub fn is_arrow(&self) -> bool {
        matches!(
            self,
            KeyEvent::Up | KeyEvent::Down | KeyEvent::Left | KeyEvent::Right
        )
    }

    #[inline]
    pub fn is_navigation(&self) -> bool {
        matches!(
            self,
            KeyEvent::Home | KeyEvent::End | KeyEvent::PageUp | KeyEvent::PageDown
        )
    }

    #[inline]
    pub fn is_function_key(&self) -> bool {
        matches!(
            self,
            KeyEvent::F1
                | KeyEvent::F2
                | KeyEvent::F3
                | KeyEvent::F4
                | KeyEvent::F5
                | KeyEvent::F6
                | KeyEvent::F7
                | KeyEvent::F8
                | KeyEvent::F9
                | KeyEvent::F10
                | KeyEvent::F11
                | KeyEvent::F12
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_roundtrip() {
        let events = [
            KeyEvent::Up,
            KeyEvent::Down,
            KeyEvent::Left,
            KeyEvent::Right,
            KeyEvent::Home,
            KeyEvent::End,
            KeyEvent::F1,
            KeyEvent::F12,
        ];

        for event in events {
            let code = event.to_code();
            let decoded = KeyEvent::from_code(code);
            assert_eq!(decoded, Some(event));
        }
    }

    #[test]
    fn test_invalid_code() {
        assert_eq!(KeyEvent::from_code(0), None);
        assert_eq!(KeyEvent::from_code(255), None);
    }

    #[test]
    fn test_is_arrow() {
        assert!(KeyEvent::Up.is_arrow());
        assert!(KeyEvent::Down.is_arrow());
        assert!(KeyEvent::Left.is_arrow());
        assert!(KeyEvent::Right.is_arrow());
        assert!(!KeyEvent::Home.is_arrow());
        assert!(!KeyEvent::F1.is_arrow());
    }

    #[test]
    fn test_is_function_key() {
        assert!(KeyEvent::F1.is_function_key());
        assert!(KeyEvent::F12.is_function_key());
        assert!(!KeyEvent::Up.is_function_key());
        assert!(!KeyEvent::Escape.is_function_key());
    }
}
