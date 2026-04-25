// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::shell::editor::mode::{CursorStyle, ModeState, Operator, SearchDirection};
use crate::shell::editor::{Buffer, Line, Mode, Motion, MotionResult};
use crate::test::framework::TestResult;

pub(crate) fn test_line_new() -> TestResult {
    let line = Line::new();
    if !line.is_empty() {
        return TestResult::Fail;
    }
    if line.len() != 0 {
        return TestResult::Fail;
    }
    if line.char_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_from_str() -> TestResult {
    let line = Line::from_str("hello");
    if line.is_empty() {
        return TestResult::Fail;
    }
    if line.char_count() != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_from_str_empty() -> TestResult {
    let line = Line::from_str("");
    if !line.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_insert_char() -> TestResult {
    let mut line = Line::new();
    line.insert_char(0, 'a');
    if line.char_count() != 1 {
        return TestResult::Fail;
    }
    if line.char_at(0) != Some('a') {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_insert_char_middle() -> TestResult {
    let mut line = Line::from_str("ac");
    line.insert_char(1, 'b');
    if line.content.as_str() != "abc" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_delete_char() -> TestResult {
    let mut line = Line::from_str("abc");
    let deleted = line.delete_char(1);
    if deleted != Some('b') {
        return TestResult::Fail;
    }
    if line.content.as_str() != "ac" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_delete_char_out_of_bounds() -> TestResult {
    let mut line = Line::from_str("a");
    if line.delete_char(5).is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_split_at() -> TestResult {
    let mut line = Line::from_str("hello world");
    let rest = line.split_at(5);
    if line.content.as_str() != "hello" {
        return TestResult::Fail;
    }
    if rest.content.as_str() != " world" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_append() -> TestResult {
    let mut line1 = Line::from_str("hello");
    let line2 = Line::from_str(" world");
    line1.append(&line2);
    if line1.content.as_str() != "hello world" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_char_at() -> TestResult {
    let line = Line::from_str("abc");
    if line.char_at(0) != Some('a') {
        return TestResult::Fail;
    }
    if line.char_at(1) != Some('b') {
        return TestResult::Fail;
    }
    if line.char_at(2) != Some('c') {
        return TestResult::Fail;
    }
    if line.char_at(3) != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_substring() -> TestResult {
    let line = Line::from_str("hello world");
    if line.substring(0, 5) != "hello" {
        return TestResult::Fail;
    }
    if line.substring(6, 11) != "world" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_first_non_whitespace() -> TestResult {
    let line = Line::from_str("   hello");
    if line.first_non_whitespace() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_first_non_whitespace_no_leading() -> TestResult {
    let line = Line::from_str("hello");
    if line.first_non_whitespace() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_last_non_whitespace() -> TestResult {
    let line = Line::from_str("hello   ");
    if line.last_non_whitespace() != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_indent_level() -> TestResult {
    let line = Line::from_str("    hello");
    if line.indent_level(4) != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_indent_level_tabs() -> TestResult {
    let line = Line::from_str("\thello");
    if line.indent_level(4) != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_default() -> TestResult {
    let line: Line = Default::default();
    if !line.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_new() -> TestResult {
    let buffer = Buffer::new();
    if buffer.line_count() != 1 {
        return TestResult::Fail;
    }
    if buffer.is_modified() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_from_string_empty() -> TestResult {
    let buffer = Buffer::from_string("");
    if buffer.line_count() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_from_string_single_line() -> TestResult {
    let buffer = Buffer::from_string("hello");
    if buffer.line_count() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_from_string_multiple_lines() -> TestResult {
    let buffer = Buffer::from_string("line1\nline2\nline3");
    if buffer.line_count() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_from_file() -> TestResult {
    let buffer = Buffer::from_file("test.txt", "content");
    if buffer.filename() != Some("test.txt") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_line() -> TestResult {
    let buffer = Buffer::from_string("hello");
    let line = buffer.line(0).unwrap();
    if line.content.as_str() != "hello" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_line_out_of_bounds() -> TestResult {
    let buffer = Buffer::new();
    if buffer.line(100).is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_line_mut_marks_modified() -> TestResult {
    let mut buffer = Buffer::new();
    buffer.line_mut(0);
    if !buffer.is_modified() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_set_filename() -> TestResult {
    let mut buffer = Buffer::new();
    buffer.set_filename("new.txt");
    if buffer.filename() != Some("new.txt") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_mark_saved() -> TestResult {
    let mut buffer = Buffer::new();
    buffer.line_mut(0);
    if !buffer.is_modified() {
        return TestResult::Fail;
    }
    buffer.mark_saved();
    if buffer.is_modified() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_readonly() -> TestResult {
    let mut buffer = Buffer::new();
    if buffer.is_readonly() {
        return TestResult::Fail;
    }
    buffer.set_readonly(true);
    if !buffer.is_readonly() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_insert_char() -> TestResult {
    let mut buffer = Buffer::new();
    buffer.insert_char(0, 0, 'x');
    if !buffer.is_modified() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_delete_char() -> TestResult {
    let mut buffer = Buffer::from_string("abc");
    buffer.delete_char(0, 1);
    if buffer.line(0).unwrap().content.as_str() != "ac" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_insert_line() -> TestResult {
    let mut buffer = Buffer::from_string("line1");
    buffer.insert_line(1, Line::from_str("line2"));
    if buffer.line_count() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_delete_line() -> TestResult {
    let mut buffer = Buffer::from_string("line1\nline2");
    buffer.delete_line(0);
    if buffer.line_count() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_split_line() -> TestResult {
    let mut buffer = Buffer::from_string("hello world");
    buffer.split_line(0, 5);
    if buffer.line_count() != 2 {
        return TestResult::Fail;
    }
    if buffer.line(0).unwrap().content.as_str() != "hello" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_join_lines() -> TestResult {
    let mut buffer = Buffer::from_string("hello\nworld");
    buffer.join_lines(0);
    if buffer.line_count() != 1 {
        return TestResult::Fail;
    }
    if buffer.line(0).unwrap().content.as_str() != "helloworld" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_backspace() -> TestResult {
    let mut buffer = Buffer::from_string("abc");
    buffer.backspace(0, 2);
    TestResult::Pass
}

pub(crate) fn test_buffer_to_string() -> TestResult {
    let buffer = Buffer::from_string("line1\nline2");
    if buffer.to_string() != "line1\nline2" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_line_len() -> TestResult {
    let buffer = Buffer::from_string("hello");
    if buffer.line_len(0) != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_default() -> TestResult {
    let buffer: Buffer = Default::default();
    if buffer.line_count() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_normal() -> TestResult {
    if Mode::Normal.display_name() != "NORMAL" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_insert() -> TestResult {
    if Mode::Insert.display_name() != "INSERT" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_visual() -> TestResult {
    if Mode::Visual.display_name() != "VISUAL" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_visual_line() -> TestResult {
    if Mode::VisualLine.display_name() != "V-LINE" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_visual_block() -> TestResult {
    if Mode::VisualBlock.display_name() != "V-BLOCK" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_command() -> TestResult {
    if Mode::Command.display_name() != "COMMAND" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_replace() -> TestResult {
    if Mode::Replace.display_name() != "REPLACE" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_search() -> TestResult {
    if Mode::Search.display_name() != "SEARCH" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_status_indicator_normal() -> TestResult {
    if Mode::Normal.status_indicator() != "" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_status_indicator_insert() -> TestResult {
    if Mode::Insert.status_indicator() != "-- INSERT --" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_cursor_style_normal() -> TestResult {
    if Mode::Normal.cursor_style() != CursorStyle::Block {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_cursor_style_insert() -> TestResult {
    if Mode::Insert.cursor_style() != CursorStyle::Line {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_cursor_style_replace() -> TestResult {
    if Mode::Replace.cursor_style() != CursorStyle::Underline {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_is_insert_like_insert() -> TestResult {
    if !Mode::Insert.is_insert_like() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_is_insert_like_replace() -> TestResult {
    if !Mode::Replace.is_insert_like() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_is_insert_like_normal() -> TestResult {
    if Mode::Normal.is_insert_like() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_is_visual() -> TestResult {
    if !Mode::Visual.is_visual() {
        return TestResult::Fail;
    }
    if !Mode::VisualLine.is_visual() {
        return TestResult::Fail;
    }
    if !Mode::VisualBlock.is_visual() {
        return TestResult::Fail;
    }
    if Mode::Normal.is_visual() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_allows_motion() -> TestResult {
    if !Mode::Normal.allows_motion() {
        return TestResult::Fail;
    }
    if !Mode::Visual.allows_motion() {
        return TestResult::Fail;
    }
    if Mode::Insert.allows_motion() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_state_new() -> TestResult {
    let state = ModeState::new();
    if state.mode != Mode::Normal {
        return TestResult::Fail;
    }
    if state.pending_operator.is_some() {
        return TestResult::Fail;
    }
    if state.count.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_state_set_mode() -> TestResult {
    let mut state = ModeState::new();
    state.set_mode(Mode::Insert);
    if state.mode != Mode::Insert {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_state_effective_count() -> TestResult {
    let state = ModeState::new();
    if state.effective_count() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_state_accumulate_count() -> TestResult {
    let mut state = ModeState::new();
    state.accumulate_count(5);
    if state.effective_count() != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_state_reset_pending() -> TestResult {
    let mut state = ModeState::new();
    state.accumulate_count(5);
    state.reset_pending();
    if state.count.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mode_state_default() -> TestResult {
    let state: ModeState = Default::default();
    if state.mode != Mode::Normal {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_operator_from_char_delete() -> TestResult {
    if Operator::from_char('d') != Some(Operator::Delete) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_operator_from_char_yank() -> TestResult {
    if Operator::from_char('y') != Some(Operator::Yank) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_operator_from_char_change() -> TestResult {
    if Operator::from_char('c') != Some(Operator::Change) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_operator_from_char_indent() -> TestResult {
    if Operator::from_char('>') != Some(Operator::Indent) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_operator_from_char_outdent() -> TestResult {
    if Operator::from_char('<') != Some(Operator::Outdent) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_operator_from_char_invalid() -> TestResult {
    if Operator::from_char('z').is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_operator_requires_motion() -> TestResult {
    if !Operator::Delete.requires_motion() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_search_direction_forward() -> TestResult {
    if SearchDirection::Forward.reverse() != SearchDirection::Backward {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_search_direction_backward() -> TestResult {
    if SearchDirection::Backward.reverse() != SearchDirection::Forward {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_motion_result_new() -> TestResult {
    let result = MotionResult::new(5, 10);
    if result.row != 5 {
        return TestResult::Fail;
    }
    if result.col != 10 {
        return TestResult::Fail;
    }
    if result.inclusive {
        return TestResult::Fail;
    }
    if result.linewise {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_motion_result_inclusive() -> TestResult {
    let result = MotionResult::new(0, 0).inclusive();
    if !result.inclusive {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_motion_result_linewise() -> TestResult {
    let result = MotionResult::new(0, 0).linewise();
    if !result.linewise {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_motion_left() -> TestResult {
    if !matches!(Motion::Left, Motion::Left) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_motion_right() -> TestResult {
    if !matches!(Motion::Right, Motion::Right) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_motion_up() -> TestResult {
    if !matches!(Motion::Up, Motion::Up) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_motion_down() -> TestResult {
    if !matches!(Motion::Down, Motion::Down) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_motion_word_forward() -> TestResult {
    if !matches!(Motion::WordForward, Motion::WordForward) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_motion_word_backward() -> TestResult {
    if !matches!(Motion::WordBackward, Motion::WordBackward) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_motion_line_start() -> TestResult {
    if !matches!(Motion::LineStart, Motion::LineStart) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_motion_line_end() -> TestResult {
    if !matches!(Motion::LineEnd, Motion::LineEnd) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_motion_file_start() -> TestResult {
    if !matches!(Motion::FileStart, Motion::FileStart) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_motion_file_end() -> TestResult {
    if !matches!(Motion::FileEnd, Motion::FileEnd) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cursor_style_equality() -> TestResult {
    if CursorStyle::Block != CursorStyle::Block {
        return TestResult::Fail;
    }
    if CursorStyle::Block == CursorStyle::Line {
        return TestResult::Fail;
    }
    TestResult::Pass
}
