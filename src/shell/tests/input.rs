// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::shell::terminal::input::{LineEditor, MAX_INPUT_LEN, PROMPT_LEN};
use crate::test::framework::TestResult;

pub(crate) fn test_line_editor_new() -> TestResult {
    let editor = LineEditor::new();
    if editor.length() != 0 {
        return TestResult::Fail;
    }
    if editor.cursor_pos() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_reset() -> TestResult {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.insert_char(b'b');
    editor.reset(5);
    if editor.length() != 0 {
        return TestResult::Fail;
    }
    if editor.cursor_pos() != 0 {
        return TestResult::Fail;
    }
    if editor.row() != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_set_row() -> TestResult {
    let mut editor = LineEditor::new();
    editor.set_row(10);
    if editor.row() != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_row() -> TestResult {
    let mut editor = LineEditor::new();
    editor.reset(7);
    if editor.row() != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_get_content_empty() -> TestResult {
    let editor = LineEditor::new();
    if editor.get_content() != b"" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_get_content() -> TestResult {
    let mut editor = LineEditor::new();
    editor.insert_char(b'h');
    editor.insert_char(b'i');
    if editor.get_content() != b"hi" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_length() -> TestResult {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.insert_char(b'b');
    editor.insert_char(b'c');
    if editor.length() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_cursor_pos() -> TestResult {
    let mut editor = LineEditor::new();
    editor.insert_char(b'x');
    if editor.cursor_pos() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_cursor_col() -> TestResult {
    let editor = LineEditor::new();
    if editor.cursor_col() != PROMPT_LEN as u32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_cursor_col_after_input() -> TestResult {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.insert_char(b'b');
    if editor.cursor_col() != PROMPT_LEN as u32 + 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_set_content() -> TestResult {
    let mut editor = LineEditor::new();
    editor.set_content(b"test content");
    if editor.get_content() != b"test content" {
        return TestResult::Fail;
    }
    if editor.cursor_pos() != 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_set_content_truncates() -> TestResult {
    let mut editor = LineEditor::new();
    let long_content = [b'x'; MAX_INPUT_LEN + 50];
    editor.set_content(&long_content);
    if editor.length() > MAX_INPUT_LEN - 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_insert_char() -> TestResult {
    let mut editor = LineEditor::new();
    editor.insert_char(b'A');
    if editor.length() != 1 {
        return TestResult::Fail;
    }
    if editor.cursor_pos() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_insert_char_multiple() -> TestResult {
    let mut editor = LineEditor::new();
    editor.insert_char(b'H');
    editor.insert_char(b'e');
    editor.insert_char(b'l');
    editor.insert_char(b'l');
    editor.insert_char(b'o');
    if editor.get_content() != b"Hello" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_insert_char_at_middle() -> TestResult {
    let mut editor = LineEditor::new();
    editor.insert_char(b'A');
    editor.insert_char(b'C');
    editor.move_left();
    editor.insert_char(b'B');
    if editor.get_content() != b"ABC" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_delete_char() -> TestResult {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.insert_char(b'b');
    editor.insert_char(b'c');
    editor.move_left();
    editor.delete_char();
    if editor.get_content() != b"ac" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_delete_char_at_end() -> TestResult {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.delete_char();
    if editor.get_content() != b"a" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_backspace() -> TestResult {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.insert_char(b'b');
    editor.backspace();
    if editor.get_content() != b"a" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_backspace_at_start() -> TestResult {
    let mut editor = LineEditor::new();
    editor.backspace();
    if editor.length() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_move_left() -> TestResult {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.insert_char(b'b');
    editor.move_left();
    if editor.cursor_pos() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_move_left_at_start() -> TestResult {
    let mut editor = LineEditor::new();
    editor.move_left();
    if editor.cursor_pos() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_move_right() -> TestResult {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.insert_char(b'b');
    editor.move_left();
    editor.move_left();
    editor.move_right();
    if editor.cursor_pos() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_move_right_at_end() -> TestResult {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.move_right();
    if editor.cursor_pos() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_move_home() -> TestResult {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.insert_char(b'b');
    editor.insert_char(b'c');
    editor.move_home();
    if editor.cursor_pos() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_move_end() -> TestResult {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.insert_char(b'b');
    editor.move_home();
    editor.move_end();
    if editor.cursor_pos() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_move_word_left() -> TestResult {
    let mut editor = LineEditor::new();
    editor.set_content(b"one two three");
    editor.move_word_left();
    if editor.cursor_pos() >= 13 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_move_word_left_at_start() -> TestResult {
    let mut editor = LineEditor::new();
    editor.set_content(b"test");
    editor.move_home();
    editor.move_word_left();
    if editor.cursor_pos() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_move_word_right() -> TestResult {
    let mut editor = LineEditor::new();
    editor.set_content(b"one two three");
    editor.move_home();
    editor.move_word_right();
    if editor.cursor_pos() <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_delete_word_left() -> TestResult {
    let mut editor = LineEditor::new();
    editor.set_content(b"hello world");
    editor.delete_word_left();
    if editor.get_content() != b"hello " {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_delete_word_left_at_start() -> TestResult {
    let mut editor = LineEditor::new();
    editor.set_content(b"test");
    editor.move_home();
    editor.delete_word_left();
    if editor.get_content() != b"test" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_delete_to_end() -> TestResult {
    let mut editor = LineEditor::new();
    editor.set_content(b"hello world");
    editor.move_home();
    editor.move_right();
    editor.move_right();
    editor.move_right();
    editor.move_right();
    editor.move_right();
    editor.delete_to_end();
    if editor.get_content() != b"hello" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_delete_to_start() -> TestResult {
    let mut editor = LineEditor::new();
    editor.set_content(b"hello world");
    editor.move_home();
    for _ in 0..6 {
        editor.move_right();
    }
    editor.delete_to_start();
    if editor.get_content() != b"world" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_delete_to_start_at_beginning() -> TestResult {
    let mut editor = LineEditor::new();
    editor.set_content(b"test");
    editor.move_home();
    editor.delete_to_start();
    if editor.get_content() != b"test" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_clear_line() -> TestResult {
    let mut editor = LineEditor::new();
    editor.set_content(b"some content");
    editor.clear_line();
    if editor.length() != 0 {
        return TestResult::Fail;
    }
    if editor.cursor_pos() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_input_len_constant() -> TestResult {
    if MAX_INPUT_LEN != 240 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_prompt_len_constant() -> TestResult {
    if PROMPT_LEN != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_line_editor_insert_at_max_length() -> TestResult {
    let mut editor = LineEditor::new();
    for _ in 0..MAX_INPUT_LEN {
        editor.insert_char(b'x');
    }
    let len_before = editor.length();
    editor.insert_char(b'y');
    if editor.length() != len_before {
        return TestResult::Fail;
    }
    TestResult::Pass
}
