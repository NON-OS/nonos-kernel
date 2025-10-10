#![allow(dead_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Left,
    Right,
    Enter,
    Esc,       // keep enum for future use, but we won't emit it
    Unknown,
}

#[derive(Clone, Copy, Debug)]
pub struct KeyEvent {
    pub key: Key,
}

pub fn poll_event() -> Option<KeyEvent> {
    use crate::arch::x86_64::keyboard::{get_event_blocking, KeyCode};
    if let Some(kc) = get_event_blocking() {
        let key = match kc {
            KeyCode::Up    => Key::Up,
            KeyCode::Down  => Key::Down,
            KeyCode::Left  => Key::Left,
            KeyCode::Right => Key::Right,
            KeyCode::Enter => Key::Enter,
            // KeyCode::Esc => Key::Esc, // not present in your enum -> don't match it
            _ => Key::Unknown,
        };
        Some(KeyEvent { key })
    } else {
        None
    }
}
