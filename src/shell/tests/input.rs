use crate::shell::terminal::input::{LineEditor, MAX_INPUT_LEN, PROMPT_LEN};

#[test]
fn test_line_editor_new() {
    let editor = LineEditor::new();
    assert_eq!(editor.length(), 0);
    assert_eq!(editor.cursor_pos(), 0);
}

#[test]
fn test_line_editor_reset() {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.insert_char(b'b');
    editor.reset(5);
    assert_eq!(editor.length(), 0);
    assert_eq!(editor.cursor_pos(), 0);
    assert_eq!(editor.row(), 5);
}

#[test]
fn test_line_editor_set_row() {
    let mut editor = LineEditor::new();
    editor.set_row(10);
    assert_eq!(editor.row(), 10);
}

#[test]
fn test_line_editor_row() {
    let mut editor = LineEditor::new();
    editor.reset(7);
    assert_eq!(editor.row(), 7);
}

#[test]
fn test_line_editor_get_content_empty() {
    let editor = LineEditor::new();
    assert_eq!(editor.get_content(), b"");
}

#[test]
fn test_line_editor_get_content() {
    let mut editor = LineEditor::new();
    editor.insert_char(b'h');
    editor.insert_char(b'i');
    assert_eq!(editor.get_content(), b"hi");
}

#[test]
fn test_line_editor_length() {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.insert_char(b'b');
    editor.insert_char(b'c');
    assert_eq!(editor.length(), 3);
}

#[test]
fn test_line_editor_cursor_pos() {
    let mut editor = LineEditor::new();
    editor.insert_char(b'x');
    assert_eq!(editor.cursor_pos(), 1);
}

#[test]
fn test_line_editor_cursor_col() {
    let editor = LineEditor::new();
    assert_eq!(editor.cursor_col(), PROMPT_LEN as u32);
}

#[test]
fn test_line_editor_cursor_col_after_input() {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.insert_char(b'b');
    assert_eq!(editor.cursor_col(), PROMPT_LEN as u32 + 2);
}

#[test]
fn test_line_editor_set_content() {
    let mut editor = LineEditor::new();
    editor.set_content(b"test content");
    assert_eq!(editor.get_content(), b"test content");
    assert_eq!(editor.cursor_pos(), 12);
}

#[test]
fn test_line_editor_set_content_truncates() {
    let mut editor = LineEditor::new();
    let long_content = [b'x'; MAX_INPUT_LEN + 50];
    editor.set_content(&long_content);
    assert!(editor.length() <= MAX_INPUT_LEN - 1);
}

#[test]
fn test_line_editor_insert_char() {
    let mut editor = LineEditor::new();
    editor.insert_char(b'A');
    assert_eq!(editor.length(), 1);
    assert_eq!(editor.cursor_pos(), 1);
}

#[test]
fn test_line_editor_insert_char_multiple() {
    let mut editor = LineEditor::new();
    editor.insert_char(b'H');
    editor.insert_char(b'e');
    editor.insert_char(b'l');
    editor.insert_char(b'l');
    editor.insert_char(b'o');
    assert_eq!(editor.get_content(), b"Hello");
}

#[test]
fn test_line_editor_insert_char_at_middle() {
    let mut editor = LineEditor::new();
    editor.insert_char(b'A');
    editor.insert_char(b'C');
    editor.move_left();
    editor.insert_char(b'B');
    assert_eq!(editor.get_content(), b"ABC");
}

#[test]
fn test_line_editor_delete_char() {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.insert_char(b'b');
    editor.insert_char(b'c');
    editor.move_left();
    editor.delete_char();
    assert_eq!(editor.get_content(), b"ac");
}

#[test]
fn test_line_editor_delete_char_at_end() {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.delete_char();
    assert_eq!(editor.get_content(), b"a");
}

#[test]
fn test_line_editor_backspace() {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.insert_char(b'b');
    editor.backspace();
    assert_eq!(editor.get_content(), b"a");
}

#[test]
fn test_line_editor_backspace_at_start() {
    let mut editor = LineEditor::new();
    editor.backspace();
    assert_eq!(editor.length(), 0);
}

#[test]
fn test_line_editor_move_left() {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.insert_char(b'b');
    editor.move_left();
    assert_eq!(editor.cursor_pos(), 1);
}

#[test]
fn test_line_editor_move_left_at_start() {
    let mut editor = LineEditor::new();
    editor.move_left();
    assert_eq!(editor.cursor_pos(), 0);
}

#[test]
fn test_line_editor_move_right() {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.insert_char(b'b');
    editor.move_left();
    editor.move_left();
    editor.move_right();
    assert_eq!(editor.cursor_pos(), 1);
}

#[test]
fn test_line_editor_move_right_at_end() {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.move_right();
    assert_eq!(editor.cursor_pos(), 1);
}

#[test]
fn test_line_editor_move_home() {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.insert_char(b'b');
    editor.insert_char(b'c');
    editor.move_home();
    assert_eq!(editor.cursor_pos(), 0);
}

#[test]
fn test_line_editor_move_end() {
    let mut editor = LineEditor::new();
    editor.insert_char(b'a');
    editor.insert_char(b'b');
    editor.move_home();
    editor.move_end();
    assert_eq!(editor.cursor_pos(), 2);
}

#[test]
fn test_line_editor_move_word_left() {
    let mut editor = LineEditor::new();
    editor.set_content(b"one two three");
    editor.move_word_left();
    assert!(editor.cursor_pos() < 13);
}

#[test]
fn test_line_editor_move_word_left_at_start() {
    let mut editor = LineEditor::new();
    editor.set_content(b"test");
    editor.move_home();
    editor.move_word_left();
    assert_eq!(editor.cursor_pos(), 0);
}

#[test]
fn test_line_editor_move_word_right() {
    let mut editor = LineEditor::new();
    editor.set_content(b"one two three");
    editor.move_home();
    editor.move_word_right();
    assert!(editor.cursor_pos() > 0);
}

#[test]
fn test_line_editor_delete_word_left() {
    let mut editor = LineEditor::new();
    editor.set_content(b"hello world");
    editor.delete_word_left();
    assert_eq!(editor.get_content(), b"hello ");
}

#[test]
fn test_line_editor_delete_word_left_at_start() {
    let mut editor = LineEditor::new();
    editor.set_content(b"test");
    editor.move_home();
    editor.delete_word_left();
    assert_eq!(editor.get_content(), b"test");
}

#[test]
fn test_line_editor_delete_to_end() {
    let mut editor = LineEditor::new();
    editor.set_content(b"hello world");
    editor.move_home();
    editor.move_right();
    editor.move_right();
    editor.move_right();
    editor.move_right();
    editor.move_right();
    editor.delete_to_end();
    assert_eq!(editor.get_content(), b"hello");
}

#[test]
fn test_line_editor_delete_to_start() {
    let mut editor = LineEditor::new();
    editor.set_content(b"hello world");
    editor.move_home();
    for _ in 0..6 {
        editor.move_right();
    }
    editor.delete_to_start();
    assert_eq!(editor.get_content(), b"world");
}

#[test]
fn test_line_editor_delete_to_start_at_beginning() {
    let mut editor = LineEditor::new();
    editor.set_content(b"test");
    editor.move_home();
    editor.delete_to_start();
    assert_eq!(editor.get_content(), b"test");
}

#[test]
fn test_line_editor_clear_line() {
    let mut editor = LineEditor::new();
    editor.set_content(b"some content");
    editor.clear_line();
    assert_eq!(editor.length(), 0);
    assert_eq!(editor.cursor_pos(), 0);
}

#[test]
fn test_max_input_len_constant() {
    assert_eq!(MAX_INPUT_LEN, 240);
}

#[test]
fn test_prompt_len_constant() {
    assert_eq!(PROMPT_LEN, 7);
}

#[test]
fn test_line_editor_insert_at_max_length() {
    let mut editor = LineEditor::new();
    for _ in 0..MAX_INPUT_LEN {
        editor.insert_char(b'x');
    }
    let len_before = editor.length();
    editor.insert_char(b'y');
    assert_eq!(editor.length(), len_before);
}
