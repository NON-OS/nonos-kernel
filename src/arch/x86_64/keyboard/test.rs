//! Unit Tests for Keyboard Layouts and Event Mapping

#[cfg(test)]
mod tests {
    use super::super::layout::{get_ascii_mapping, Layout};

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
