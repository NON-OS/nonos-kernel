#[cfg(test)]
mod tests {
    use crate::apps::ecosystem::browser::engine::layout::inline::*;

    #[test]
    fn test_break_into_lines_fits_one_line() {
        let lines = break_into_lines("hello world", 200.0, 8.0, 20.0, 0.0, None);
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn test_break_into_lines_wraps() {
        let lines = break_into_lines("hello world foo bar", 80.0, 8.0, 20.0, 0.0, None);
        assert!(lines.len() > 1);
    }

    #[test]
    fn test_line_box_remaining_width() {
        let line = LineBox::new(0.0, 20.0);
        assert!((line.remaining_width(100.0) - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_text_align_center() {
        let mut line = LineBox::new(0.0, 20.0);
        line.add_fragment(alloc::string::String::from("hi"), 8.0, None);
        apply_text_alignment(&mut line, 200.0, super::super::super::css::cascade::TextAlign::Center);
        let x = line.fragments[0].x;
        assert!(x > 80.0);
    }

    #[test]
    fn test_text_align_right() {
        let mut line = LineBox::new(0.0, 20.0);
        line.add_fragment(alloc::string::String::from("hi"), 8.0, None);
        apply_text_alignment(&mut line, 200.0, super::super::super::css::cascade::TextAlign::Right);
        let x = line.fragments[0].x;
        assert!(x > 150.0);
    }

    #[test]
    fn test_line_y_advances() {
        let lines = break_into_lines("hello world foo bar baz qux", 80.0, 8.0, 20.0, 0.0, None);
        if lines.len() > 1 {
            assert!((lines[1].y - 20.0).abs() < 0.01);
        }
    }
}
