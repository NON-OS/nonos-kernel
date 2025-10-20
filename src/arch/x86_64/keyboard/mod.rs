//! NØNOS Keyboard Subsystem

pub mod input;
pub mod keymap;
pub mod layout;
pub mod ps2;
pub mod usb_hid;
pub mod test;

/// KeyCode enum representing logical keys
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCode {
    A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z,
    Num0, Num1, Num2, Num3, Num4, Num5, Num6, Num7, Num8, Num9,
    Space, Enter, Escape, Backspace, Tab,
    Char(char),
    Unknown,
}

/// Handle keyboard interrupt
pub fn handle_keyboard_interrupt() {
    let scan_code = crate::arch::x86_64::port::inb(0x60);
    input::push_event(input::InputEvent::KeyPress(scan_code));
}

/// Prelude for ergonomic import of all keyboard APIs.
pub mod prelude {
    pub use super::input::*;
    pub use super::keymap::*;
    pub use super::layout::*;
    pub use super::ps2::*;
    pub use super::usb_hid::*;
}

#[cfg(test)]
mod tests {
    use super::layout::{get_ascii_mapping, Layout};

    #[test]
    fn mod_test_layouts() {
        let map = get_ascii_mapping(Layout::UsQwerty);
        assert_eq!(map[2], b'1');
    }
}
