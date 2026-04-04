// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::shell::editor::{Buffer, Line};

#[test]
fn test_buffer_new_empty() {
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
    let buffer = Buffer::from_string("hello world");
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
fn test_buffer_filename_none() {
    let buffer = Buffer::new();
    assert!(buffer.filename().is_none());
}

#[test]
fn test_buffer_set_filename() {
    let mut buffer = Buffer::new();
    buffer.set_filename("newfile.txt");
    assert_eq!(buffer.filename(), Some("newfile.txt"));
}

#[test]
fn test_buffer_line() {
    let buffer = Buffer::from_string("hello");
    let line = buffer.line(0);
    assert!(line.is_some());
    assert_eq!(line.unwrap().content.as_str(), "hello");
}

#[test]
fn test_buffer_line_out_of_bounds() {
    let buffer = Buffer::new();
    assert!(buffer.line(100).is_none());
}

#[test]
fn test_buffer_line_mut_marks_modified() {
    let mut buffer = Buffer::new();
    assert!(!buffer.is_modified());
    let _ = buffer.line_mut(0);
    assert!(buffer.is_modified());
}

#[test]
fn test_buffer_is_modified_false() {
    let buffer = Buffer::new();
    assert!(!buffer.is_modified());
}

#[test]
fn test_buffer_mark_saved() {
    let mut buffer = Buffer::new();
    let _ = buffer.line_mut(0);
    assert!(buffer.is_modified());
    buffer.mark_saved();
    assert!(!buffer.is_modified());
}

#[test]
fn test_buffer_is_readonly_default() {
    let buffer = Buffer::new();
    assert!(!buffer.is_readonly());
}

#[test]
fn test_buffer_set_readonly() {
    let mut buffer = Buffer::new();
    buffer.set_readonly(true);
    assert!(buffer.is_readonly());
}

#[test]
fn test_buffer_insert_char() {
    let mut buffer = Buffer::new();
    buffer.insert_char(0, 0, 'a');
    assert!(buffer.is_modified());
}

#[test]
fn test_buffer_delete_char() {
    let mut buffer = Buffer::from_string("abc");
    let deleted = buffer.delete_char(0, 1);
    assert_eq!(deleted, Some('b'));
}

#[test]
fn test_buffer_delete_char_out_of_bounds() {
    let mut buffer = Buffer::from_string("a");
    assert!(buffer.delete_char(0, 10).is_none());
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
    let deleted = buffer.delete_line(0);
    assert!(deleted.is_some());
    assert_eq!(buffer.line_count(), 1);
}

#[test]
fn test_buffer_delete_line_single() {
    let mut buffer = Buffer::from_string("only");
    let deleted = buffer.delete_line(0);
    assert!(deleted.is_some());
    assert_eq!(buffer.line_count(), 1);
    assert!(buffer.line(0).unwrap().is_empty());
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
fn test_buffer_insert_newline() {
    let mut buffer = Buffer::from_string("helloworld");
    buffer.insert_newline(0, 5);
    assert_eq!(buffer.line_count(), 2);
}

#[test]
fn test_buffer_backspace_mid_line() {
    let mut buffer = Buffer::from_string("abc");
    let (row, col) = buffer.backspace(0, 2);
    assert_eq!(row, 0);
    assert_eq!(col, 1);
}

#[test]
fn test_buffer_backspace_start_of_line() {
    let mut buffer = Buffer::from_string("hello\nworld");
    let (row, col) = buffer.backspace(1, 0);
    assert_eq!(row, 0);
}

#[test]
fn test_buffer_backspace_start_of_buffer() {
    let mut buffer = Buffer::from_string("test");
    let (row, col) = buffer.backspace(0, 0);
    assert_eq!(row, 0);
    assert_eq!(col, 0);
}

#[test]
fn test_buffer_to_string_single() {
    let buffer = Buffer::from_string("hello");
    assert_eq!(buffer.to_string(), "hello");
}

#[test]
fn test_buffer_to_string_multiple() {
    let buffer = Buffer::from_string("line1\nline2");
    assert_eq!(buffer.to_string(), "line1\nline2");
}

#[test]
fn test_buffer_line_len() {
    let buffer = Buffer::from_string("hello");
    assert_eq!(buffer.line_len(0), 5);
}

#[test]
fn test_buffer_line_len_out_of_bounds() {
    let buffer = Buffer::new();
    assert_eq!(buffer.line_len(100), 0);
}

#[test]
fn test_buffer_total_chars() {
    let buffer = Buffer::from_string("hello\nworld");
    assert!(buffer.total_chars() > 0);
}

#[test]
fn test_buffer_lines_slice() {
    let buffer = Buffer::from_string("a\nb\nc");
    assert_eq!(buffer.lines().len(), 3);
}

#[test]
fn test_buffer_default() {
    let buffer: Buffer = Default::default();
    assert_eq!(buffer.line_count(), 1);
}

#[test]
fn test_buffer_clone() {
    let buffer1 = Buffer::from_string("test");
    let buffer2 = buffer1.clone();
    assert_eq!(buffer1.line_count(), buffer2.line_count());
}

#[test]
fn test_buffer_debug() {
    let buffer = Buffer::from_string("test");
    let debug_str = alloc::format!("{:?}", buffer);
    assert!(debug_str.contains("Buffer"));
}

