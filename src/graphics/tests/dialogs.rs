use crate::graphics::window::dialogs::*;

#[test]
fn test_max_message_len() {
    assert_eq!(MAX_MESSAGE_LEN, 128);
}

#[test]
fn test_max_title_len() {
    assert_eq!(MAX_TITLE_LEN, 32);
}

#[test]
fn test_max_input_len() {
    assert_eq!(MAX_INPUT_LEN, 64);
}

#[test]
fn test_dialog_type_values() {
    assert_eq!(DIALOG_INFO, 0);
    assert_eq!(DIALOG_WARNING, 1);
    assert_eq!(DIALOG_ERROR, 2);
    assert_eq!(DIALOG_CONFIRM, 3);
    assert_eq!(DIALOG_INPUT, 4);
}

#[test]
fn test_dialog_type_unique() {
    let types = [DIALOG_INFO, DIALOG_WARNING, DIALOG_ERROR, DIALOG_CONFIRM, DIALOG_INPUT];
    for i in 0..types.len() {
        for j in (i + 1)..types.len() {
            assert_ne!(types[i], types[j]);
        }
    }
}

#[test]
fn test_result_values() {
    assert_eq!(RESULT_NONE, 0);
    assert_eq!(RESULT_OK, 1);
    assert_eq!(RESULT_CANCEL, 2);
    assert_eq!(RESULT_YES, 3);
    assert_eq!(RESULT_NO, 4);
}

#[test]
fn test_result_values_unique() {
    let results = [RESULT_NONE, RESULT_OK, RESULT_CANCEL, RESULT_YES, RESULT_NO];
    for i in 0..results.len() {
        for j in (i + 1)..results.len() {
            assert_ne!(results[i], results[j]);
        }
    }
}

#[test]
fn test_input_callback_values() {
    assert_eq!(INPUT_CB_NONE, 0);
    assert_eq!(INPUT_CB_DESKTOP_NEW_FOLDER, 1);
    assert_eq!(INPUT_CB_DESKTOP_NEW_FILE, 2);
    assert_eq!(INPUT_CB_FM_NEW_FOLDER, 3);
    assert_eq!(INPUT_CB_FM_RENAME, 4);
}

#[test]
fn test_input_callback_unique() {
    let callbacks = [
        INPUT_CB_NONE,
        INPUT_CB_DESKTOP_NEW_FOLDER,
        INPUT_CB_DESKTOP_NEW_FILE,
        INPUT_CB_FM_NEW_FOLDER,
        INPUT_CB_FM_RENAME,
    ];
    for i in 0..callbacks.len() {
        for j in (i + 1)..callbacks.len() {
            assert_ne!(callbacks[i], callbacks[j]);
        }
    }
}

#[test]
fn test_show_and_close_dialog() {
    close();
    assert!(!is_active());

    show_dialog(DIALOG_INFO, b"Test", b"Message");
    assert!(is_active());
    assert_eq!(get_result(), RESULT_NONE);

    close();
    assert!(!is_active());
}

#[test]
fn test_dialog_types() {
    let types = [DIALOG_INFO, DIALOG_WARNING, DIALOG_ERROR, DIALOG_CONFIRM];

    for dtype in types {
        close();
        show_dialog(dtype, b"Title", b"Msg");
        assert!(is_active());
        close();
    }
}

#[test]
fn test_show_input_dialog() {
    close();
    show_input(b"Input Title", b"Enter value", INPUT_CB_FM_NEW_FOLDER);

    assert!(is_active());
    assert!(is_input_dialog());
    assert_eq!(get_input_callback(), INPUT_CB_FM_NEW_FOLDER);

    close();
    assert!(!is_active());
    assert!(!is_input_dialog());
}

#[test]
fn test_input_push_char() {
    close();
    show_input(b"Test", b"Input", INPUT_CB_NONE);

    input_push_char(b'a');
    input_push_char(b'b');
    input_push_char(b'c');

    let text = get_input_text();
    assert_eq!(text, "abc");

    close();
}

#[test]
fn test_input_pop_char() {
    close();
    show_input(b"Test", b"Input", INPUT_CB_NONE);

    input_push_char(b'x');
    input_push_char(b'y');
    input_push_char(b'z');
    input_pop_char();

    let text = get_input_text();
    assert_eq!(text, "xy");

    close();
}

#[test]
fn test_input_pop_char_empty() {
    close();
    show_input(b"Test", b"Input", INPUT_CB_NONE);

    input_pop_char();
    input_pop_char();

    let text = get_input_text();
    assert_eq!(text, "");

    close();
}

#[test]
fn test_close_resets_input() {
    close();
    show_input(b"Test", b"Input", INPUT_CB_FM_RENAME);
    input_push_char(b't');

    close();

    assert_eq!(get_input_callback(), INPUT_CB_NONE);

    close();
}

#[test]
fn test_input_max_length() {
    close();
    show_input(b"Test", b"Input", INPUT_CB_NONE);

    for _ in 0..(MAX_INPUT_LEN + 10) {
        input_push_char(b'x');
    }

    let text = get_input_text();
    assert!(text.len() < MAX_INPUT_LEN);

    close();
}

#[test]
fn test_dialog_truncates_long_title() {
    close();
    let long_title = [b'T'; 100];
    show_dialog(DIALOG_INFO, &long_title, b"Msg");
    assert!(is_active());
    close();
}

#[test]
fn test_dialog_truncates_long_message() {
    close();
    let long_msg = [b'M'; 500];
    show_dialog(DIALOG_INFO, b"Title", &long_msg);
    assert!(is_active());
    close();
}

#[test]
fn test_dialog_empty_title() {
    close();
    show_dialog(DIALOG_INFO, b"", b"Message");
    assert!(is_active());
    close();
}

#[test]
fn test_dialog_empty_message() {
    close();
    show_dialog(DIALOG_INFO, b"Title", b"");
    assert!(is_active());
    close();
}
