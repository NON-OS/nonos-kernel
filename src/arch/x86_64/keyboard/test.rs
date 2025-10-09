//! Unit Tests for Keyboard Layouts and Event Mapping

#[cfg(test)]
mod tests {
    use super::super::layouts::{get_ascii_mapping, Layout};

    #[test]
    fn test_us_qwerty_mapping() {
        let map = get_ascii_mapping(Layout::UsQwerty);
        assert_eq!(map[2], b'1');
        assert_eq!(map[16], b'q');
    }

    #[test]
    fn test_dvorak_mapping() {
        let map = get_ascii_mapping(Layout::Dvorak);
        assert_eq!(map[16], b'\'');
        assert_eq!(map[30], b'a');
    }

    // Add more tests later for AZERTY, Colemak, etc.
}
