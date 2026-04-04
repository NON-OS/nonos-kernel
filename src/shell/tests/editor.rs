use crate::shell::editor::{Buffer, Line, Mode, Motion, MotionResult};
use crate::shell::editor::mode::{ModeState, Operator, CursorStyle, SearchDirection};

#[test]
fn test_line_new() {
    let line = Line::new();
    assert!(line.is_empty());
    assert_eq!(line.len(), 0);
    assert_eq!(line.char_count(), 0);
}

#[test]
fn test_line_from_str() {
    let line = Line::from_str("hello");
    assert!(!line.is_empty());
    assert_eq!(line.char_count(), 5);
}

#[test]
fn test_line_from_str_empty() {
    let line = Line::from_str("");
    assert!(line.is_empty());
}

#[test]
fn test_line_insert_char() {
    let mut line = Line::new();
    line.insert_char(0, 'a');
    assert_eq!(line.char_count(), 1);
    assert_eq!(line.char_at(0), Some('a'));
}

#[test]
fn test_line_insert_char_middle() {
    let mut line = Line::from_str("ac");
    line.insert_char(1, 'b');
    assert_eq!(line.content.as_str(), "abc");
}

#[test]
fn test_line_delete_char() {
    let mut line = Line::from_str("abc");
    let deleted = line.delete_char(1);
    assert_eq!(deleted, Some('b'));
    assert_eq!(line.content.as_str(), "ac");
}

#[test]
fn test_line_delete_char_out_of_bounds() {
    let mut line = Line::from_str("a");
    assert!(line.delete_char(5).is_none());
}

#[test]
fn test_line_split_at() {
    let mut line = Line::from_str("hello world");
    let rest = line.split_at(5);
    assert_eq!(line.content.as_str(), "hello");
    assert_eq!(rest.content.as_str(), " world");
}

#[test]
fn test_line_append() {
    let mut line1 = Line::from_str("hello");
    let line2 = Line::from_str(" world");
    line1.append(&line2);
    assert_eq!(line1.content.as_str(), "hello world");
}

#[test]
fn test_line_char_at() {
    let line = Line::from_str("abc");
    assert_eq!(line.char_at(0), Some('a'));
    assert_eq!(line.char_at(1), Some('b'));
    assert_eq!(line.char_at(2), Some('c'));
    assert_eq!(line.char_at(3), None);
}

#[test]
fn test_line_substring() {
    let line = Line::from_str("hello world");
    assert_eq!(line.substring(0, 5), "hello");
    assert_eq!(line.substring(6, 11), "world");
}

#[test]
fn test_line_first_non_whitespace() {
    let line = Line::from_str("   hello");
    assert_eq!(line.first_non_whitespace(), 3);
}

#[test]
fn test_line_first_non_whitespace_no_leading() {
    let line = Line::from_str("hello");
    assert_eq!(line.first_non_whitespace(), 0);
}

#[test]
fn test_line_last_non_whitespace() {
    let line = Line::from_str("hello   ");
    assert_eq!(line.last_non_whitespace(), 4);
}

#[test]
fn test_line_indent_level() {
    let line = Line::from_str("    hello");
    assert_eq!(line.indent_level(4), 4);
}

#[test]
fn test_line_indent_level_tabs() {
    let line = Line::from_str("\thello");
    assert_eq!(line.indent_level(4), 4);
}

#[test]
fn test_line_default() {
    let line: Line = Default::default();
    assert!(line.is_empty());
}

#[test]
fn test_buffer_new() {
    let buffer = Buffer::new();
    assert_eq!(buffer.line_count(), 1);
    assert!(!buffer.is_modified());
}

#[test]
fn test_buffer_from_string_empty() {
    let buffer = Buffer::from_string("");
    assert_eq!(buffer.line_count(), 1);
}

#[test]
fn test_buffer_from_string_single_line() {
    let buffer = Buffer::from_string("hello");
    assert_eq!(buffer.line_count(), 1);
}

#[test]
fn test_buffer_from_string_multiple_lines() {
    let buffer = Buffer::from_string("line1\nline2\nline3");
    assert_eq!(buffer.line_count(), 3);
}

#[test]
fn test_buffer_from_file() {
    let buffer = Buffer::from_file("test.txt", "content");
    assert_eq!(buffer.filename(), Some("test.txt"));
}

#[test]
fn test_buffer_line() {
    let buffer = Buffer::from_string("hello");
    let line = buffer.line(0).unwrap();
    assert_eq!(line.content.as_str(), "hello");
}

#[test]
fn test_buffer_line_out_of_bounds() {
    let buffer = Buffer::new();
    assert!(buffer.line(100).is_none());
}

#[test]
fn test_buffer_line_mut_marks_modified() {
    let mut buffer = Buffer::new();
    buffer.line_mut(0);
    assert!(buffer.is_modified());
}

#[test]
fn test_buffer_set_filename() {
    let mut buffer = Buffer::new();
    buffer.set_filename("new.txt");
    assert_eq!(buffer.filename(), Some("new.txt"));
}

#[test]
fn test_buffer_mark_saved() {
    let mut buffer = Buffer::new();
    buffer.line_mut(0);
    assert!(buffer.is_modified());
    buffer.mark_saved();
    assert!(!buffer.is_modified());
}

#[test]
fn test_buffer_readonly() {
    let mut buffer = Buffer::new();
    assert!(!buffer.is_readonly());
    buffer.set_readonly(true);
    assert!(buffer.is_readonly());
}

#[test]
fn test_buffer_insert_char() {
    let mut buffer = Buffer::new();
    buffer.insert_char(0, 0, 'x');
    assert!(buffer.is_modified());
}

#[test]
fn test_buffer_delete_char() {
    let mut buffer = Buffer::from_string("abc");
    buffer.delete_char(0, 1);
    assert_eq!(buffer.line(0).unwrap().content.as_str(), "ac");
}

#[test]
fn test_buffer_insert_line() {
    let mut buffer = Buffer::from_string("line1");
    buffer.insert_line(1, Line::from_str("line2"));
    assert_eq!(buffer.line_count(), 2);
}

#[test]
fn test_buffer_delete_line() {
    let mut buffer = Buffer::from_string("line1\nline2");
    buffer.delete_line(0);
    assert_eq!(buffer.line_count(), 1);
}

#[test]
fn test_buffer_split_line() {
    let mut buffer = Buffer::from_string("hello world");
    buffer.split_line(0, 5);
    assert_eq!(buffer.line_count(), 2);
    assert_eq!(buffer.line(0).unwrap().content.as_str(), "hello");
}

#[test]
fn test_buffer_join_lines() {
    let mut buffer = Buffer::from_string("hello\nworld");
    buffer.join_lines(0);
    assert_eq!(buffer.line_count(), 1);
    assert_eq!(buffer.line(0).unwrap().content.as_str(), "helloworld");
}

#[test]
fn test_buffer_backspace() {
    let mut buffer = Buffer::from_string("abc");
    buffer.backspace(0, 2);
}

#[test]
fn test_buffer_to_string() {
    let buffer = Buffer::from_string("line1\nline2");
    assert_eq!(buffer.to_string(), "line1\nline2");
}

#[test]
fn test_buffer_line_len() {
    let buffer = Buffer::from_string("hello");
    assert_eq!(buffer.line_len(0), 5);
}

#[test]
fn test_buffer_default() {
    let buffer: Buffer = Default::default();
    assert_eq!(buffer.line_count(), 1);
}

#[test]
fn test_mode_normal() {
    assert_eq!(Mode::Normal.display_name(), "NORMAL");
}

#[test]
fn test_mode_insert() {
    assert_eq!(Mode::Insert.display_name(), "INSERT");
}

#[test]
fn test_mode_visual() {
    assert_eq!(Mode::Visual.display_name(), "VISUAL");
}

#[test]
fn test_mode_visual_line() {
    assert_eq!(Mode::VisualLine.display_name(), "V-LINE");
}

#[test]
fn test_mode_visual_block() {
    assert_eq!(Mode::VisualBlock.display_name(), "V-BLOCK");
}

#[test]
fn test_mode_command() {
    assert_eq!(Mode::Command.display_name(), "COMMAND");
}

#[test]
fn test_mode_replace() {
    assert_eq!(Mode::Replace.display_name(), "REPLACE");
}

#[test]
fn test_mode_search() {
    assert_eq!(Mode::Search.display_name(), "SEARCH");
}

#[test]
fn test_mode_status_indicator_normal() {
    assert_eq!(Mode::Normal.status_indicator(), "");
}

#[test]
fn test_mode_status_indicator_insert() {
    assert_eq!(Mode::Insert.status_indicator(), "-- INSERT --");
}

#[test]
fn test_mode_cursor_style_normal() {
    assert_eq!(Mode::Normal.cursor_style(), CursorStyle::Block);
}

#[test]
fn test_mode_cursor_style_insert() {
    assert_eq!(Mode::Insert.cursor_style(), CursorStyle::Line);
}

#[test]
fn test_mode_cursor_style_replace() {
    assert_eq!(Mode::Replace.cursor_style(), CursorStyle::Underline);
}

#[test]
fn test_mode_is_insert_like_insert() {
    assert!(Mode::Insert.is_insert_like());
}

#[test]
fn test_mode_is_insert_like_replace() {
    assert!(Mode::Replace.is_insert_like());
}

#[test]
fn test_mode_is_insert_like_normal() {
    assert!(!Mode::Normal.is_insert_like());
}

#[test]
fn test_mode_is_visual() {
    assert!(Mode::Visual.is_visual());
    assert!(Mode::VisualLine.is_visual());
    assert!(Mode::VisualBlock.is_visual());
    assert!(!Mode::Normal.is_visual());
}

#[test]
fn test_mode_allows_motion() {
    assert!(Mode::Normal.allows_motion());
    assert!(Mode::Visual.allows_motion());
    assert!(!Mode::Insert.allows_motion());
}

#[test]
fn test_mode_state_new() {
    let state = ModeState::new();
    assert_eq!(state.mode, Mode::Normal);
    assert!(state.pending_operator.is_none());
    assert!(state.count.is_none());
}

#[test]
fn test_mode_state_set_mode() {
    let mut state = ModeState::new();
    state.set_mode(Mode::Insert);
    assert_eq!(state.mode, Mode::Insert);
}

#[test]
fn test_mode_state_effective_count() {
    let state = ModeState::new();
    assert_eq!(state.effective_count(), 1);
}

#[test]
fn test_mode_state_accumulate_count() {
    let mut state = ModeState::new();
    state.accumulate_count(5);
    assert_eq!(state.effective_count(), 5);
}

#[test]
fn test_mode_state_reset_pending() {
    let mut state = ModeState::new();
    state.accumulate_count(5);
    state.reset_pending();
    assert!(state.count.is_none());
}

#[test]
fn test_mode_state_default() {
    let state: ModeState = Default::default();
    assert_eq!(state.mode, Mode::Normal);
}

#[test]
fn test_operator_from_char_delete() {
    assert_eq!(Operator::from_char('d'), Some(Operator::Delete));
}

#[test]
fn test_operator_from_char_yank() {
    assert_eq!(Operator::from_char('y'), Some(Operator::Yank));
}

#[test]
fn test_operator_from_char_change() {
    assert_eq!(Operator::from_char('c'), Some(Operator::Change));
}

#[test]
fn test_operator_from_char_indent() {
    assert_eq!(Operator::from_char('>'), Some(Operator::Indent));
}

#[test]
fn test_operator_from_char_outdent() {
    assert_eq!(Operator::from_char('<'), Some(Operator::Outdent));
}

#[test]
fn test_operator_from_char_invalid() {
    assert!(Operator::from_char('z').is_none());
}

#[test]
fn test_operator_requires_motion() {
    assert!(Operator::Delete.requires_motion());
}

#[test]
fn test_search_direction_forward() {
    assert_eq!(SearchDirection::Forward.reverse(), SearchDirection::Backward);
}

#[test]
fn test_search_direction_backward() {
    assert_eq!(SearchDirection::Backward.reverse(), SearchDirection::Forward);
}

#[test]
fn test_motion_result_new() {
    let result = MotionResult::new(5, 10);
    assert_eq!(result.row, 5);
    assert_eq!(result.col, 10);
    assert!(!result.inclusive);
    assert!(!result.linewise);
}

#[test]
fn test_motion_result_inclusive() {
    let result = MotionResult::new(0, 0).inclusive();
    assert!(result.inclusive);
}

#[test]
fn test_motion_result_linewise() {
    let result = MotionResult::new(0, 0).linewise();
    assert!(result.linewise);
}

#[test]
fn test_motion_left() {
    assert!(matches!(Motion::Left, Motion::Left));
}

#[test]
fn test_motion_right() {
    assert!(matches!(Motion::Right, Motion::Right));
}

#[test]
fn test_motion_up() {
    assert!(matches!(Motion::Up, Motion::Up));
}

#[test]
fn test_motion_down() {
    assert!(matches!(Motion::Down, Motion::Down));
}

#[test]
fn test_motion_word_forward() {
    assert!(matches!(Motion::WordForward, Motion::WordForward));
}

#[test]
fn test_motion_word_backward() {
    assert!(matches!(Motion::WordBackward, Motion::WordBackward));
}

#[test]
fn test_motion_line_start() {
    assert!(matches!(Motion::LineStart, Motion::LineStart));
}

#[test]
fn test_motion_line_end() {
    assert!(matches!(Motion::LineEnd, Motion::LineEnd));
}

#[test]
fn test_motion_file_start() {
    assert!(matches!(Motion::FileStart, Motion::FileStart));
}

#[test]
fn test_motion_file_end() {
    assert!(matches!(Motion::FileEnd, Motion::FileEnd));
}

#[test]
fn test_cursor_style_equality() {
    assert_eq!(CursorStyle::Block, CursorStyle::Block);
    assert_ne!(CursorStyle::Block, CursorStyle::Line);
}
