//! NØNOS Keyboard Subsystem

pub mod input;
pub mod keymap;
pub mod layout;
pub mod ps2;
pub mod usb_hid;
pub mod test;

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
