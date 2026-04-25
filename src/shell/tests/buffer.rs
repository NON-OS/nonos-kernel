// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::shell::editor::{Buffer, Line};
use crate::test::framework::TestResult;

pub(crate) fn test_buffer_new_empty() -> TestResult {
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
    let buffer = Buffer::from_string("hello world");
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

pub(crate) fn test_buffer_filename_none() -> TestResult {
    let buffer = Buffer::new();
    if buffer.filename().is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_set_filename() -> TestResult {
    let mut buffer = Buffer::new();
    buffer.set_filename("newfile.txt");
    if buffer.filename() != Some("newfile.txt") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_line() -> TestResult {
    let buffer = Buffer::from_string("hello");
    let line = buffer.line(0);
    if line.is_none() {
        return TestResult::Fail;
    }
    if line.unwrap().content.as_str() != "hello" {
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
    if buffer.is_modified() {
        return TestResult::Fail;
    }
    let _ = buffer.line_mut(0);
    if !buffer.is_modified() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_is_modified_false() -> TestResult {
    let buffer = Buffer::new();
    if buffer.is_modified() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_mark_saved() -> TestResult {
    let mut buffer = Buffer::new();
    let _ = buffer.line_mut(0);
    if !buffer.is_modified() {
        return TestResult::Fail;
    }
    buffer.mark_saved();
    if buffer.is_modified() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_is_readonly_default() -> TestResult {
    let buffer = Buffer::new();
    if buffer.is_readonly() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_set_readonly() -> TestResult {
    let mut buffer = Buffer::new();
    buffer.set_readonly(true);
    if !buffer.is_readonly() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_insert_char() -> TestResult {
    let mut buffer = Buffer::new();
    buffer.insert_char(0, 0, 'a');
    if !buffer.is_modified() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_delete_char() -> TestResult {
    let mut buffer = Buffer::from_string("abc");
    let deleted = buffer.delete_char(0, 1);
    if deleted != Some('b') {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_delete_char_out_of_bounds() -> TestResult {
    let mut buffer = Buffer::from_string("a");
    if buffer.delete_char(0, 10).is_some() {
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
    let deleted = buffer.delete_line(0);
    if deleted.is_none() {
        return TestResult::Fail;
    }
    if buffer.line_count() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_delete_line_single() -> TestResult {
    let mut buffer = Buffer::from_string("only");
    let deleted = buffer.delete_line(0);
    if deleted.is_none() {
        return TestResult::Fail;
    }
    if buffer.line_count() != 1 {
        return TestResult::Fail;
    }
    if !buffer.line(0).unwrap().is_empty() {
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

pub(crate) fn test_buffer_insert_newline() -> TestResult {
    let mut buffer = Buffer::from_string("helloworld");
    buffer.insert_newline(0, 5);
    if buffer.line_count() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_backspace_mid_line() -> TestResult {
    let mut buffer = Buffer::from_string("abc");
    let (row, col) = buffer.backspace(0, 2);
    if row != 0 {
        return TestResult::Fail;
    }
    if col != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_backspace_start_of_line() -> TestResult {
    let mut buffer = Buffer::from_string("hello\nworld");
    let (row, _col) = buffer.backspace(1, 0);
    if row != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_backspace_start_of_buffer() -> TestResult {
    let mut buffer = Buffer::from_string("test");
    let (row, col) = buffer.backspace(0, 0);
    if row != 0 {
        return TestResult::Fail;
    }
    if col != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_to_string_single() -> TestResult {
    let buffer = Buffer::from_string("hello");
    if buffer.to_string() != "hello" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_to_string_multiple() -> TestResult {
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

pub(crate) fn test_buffer_line_len_out_of_bounds() -> TestResult {
    let buffer = Buffer::new();
    if buffer.line_len(100) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_total_chars() -> TestResult {
    let buffer = Buffer::from_string("hello\nworld");
    if buffer.total_chars() <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_lines_slice() -> TestResult {
    let buffer = Buffer::from_string("a\nb\nc");
    if buffer.lines().len() != 3 {
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

pub(crate) fn test_buffer_clone() -> TestResult {
    let buffer1 = Buffer::from_string("test");
    let buffer2 = buffer1.clone();
    if buffer1.line_count() != buffer2.line_count() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buffer_debug() -> TestResult {
    let buffer = Buffer::from_string("test");
    let debug_str = alloc::format!("{:?}", buffer);
    if !debug_str.contains("Buffer") {
        return TestResult::Fail;
    }
    TestResult::Pass
}
