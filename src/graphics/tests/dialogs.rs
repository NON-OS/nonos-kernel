use crate::graphics::window::dialogs::*;
use crate::test::framework::TestResult;

pub(crate) fn test_max_message_len() -> TestResult {
    if MAX_MESSAGE_LEN != 128 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_title_len() -> TestResult {
    if MAX_TITLE_LEN != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_input_len() -> TestResult {
    if MAX_INPUT_LEN != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dialog_type_values() -> TestResult {
    if DIALOG_INFO != 0 {
        return TestResult::Fail;
    }
    if DIALOG_WARNING != 1 {
        return TestResult::Fail;
    }
    if DIALOG_ERROR != 2 {
        return TestResult::Fail;
    }
    if DIALOG_CONFIRM != 3 {
        return TestResult::Fail;
    }
    if DIALOG_INPUT != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dialog_type_unique() -> TestResult {
    let types = [DIALOG_INFO, DIALOG_WARNING, DIALOG_ERROR, DIALOG_CONFIRM, DIALOG_INPUT];
    for i in 0..types.len() {
        for j in (i + 1)..types.len() {
            if types[i] == types[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_result_values() -> TestResult {
    if RESULT_NONE != 0 {
        return TestResult::Fail;
    }
    if RESULT_OK != 1 {
        return TestResult::Fail;
    }
    if RESULT_CANCEL != 2 {
        return TestResult::Fail;
    }
    if RESULT_YES != 3 {
        return TestResult::Fail;
    }
    if RESULT_NO != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_result_values_unique() -> TestResult {
    let results = [RESULT_NONE, RESULT_OK, RESULT_CANCEL, RESULT_YES, RESULT_NO];
    for i in 0..results.len() {
        for j in (i + 1)..results.len() {
            if results[i] == results[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_input_callback_values() -> TestResult {
    if INPUT_CB_NONE != 0 {
        return TestResult::Fail;
    }
    if INPUT_CB_DESKTOP_NEW_FOLDER != 1 {
        return TestResult::Fail;
    }
    if INPUT_CB_DESKTOP_NEW_FILE != 2 {
        return TestResult::Fail;
    }
    if INPUT_CB_FM_NEW_FOLDER != 3 {
        return TestResult::Fail;
    }
    if INPUT_CB_FM_RENAME != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_input_callback_unique() -> TestResult {
    let callbacks = [
        INPUT_CB_NONE,
        INPUT_CB_DESKTOP_NEW_FOLDER,
        INPUT_CB_DESKTOP_NEW_FILE,
        INPUT_CB_FM_NEW_FOLDER,
        INPUT_CB_FM_RENAME,
    ];
    for i in 0..callbacks.len() {
        for j in (i + 1)..callbacks.len() {
            if callbacks[i] == callbacks[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_show_and_close_dialog() -> TestResult {
    close();
    if is_active() {
        return TestResult::Fail;
    }

    show_dialog(DIALOG_INFO, b"Test", b"Message");
    if !is_active() {
        return TestResult::Fail;
    }
    if get_result() != RESULT_NONE {
        return TestResult::Fail;
    }

    close();
    if is_active() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dialog_types() -> TestResult {
    let types = [DIALOG_INFO, DIALOG_WARNING, DIALOG_ERROR, DIALOG_CONFIRM];

    for dtype in types {
        close();
        show_dialog(dtype, b"Title", b"Msg");
        if !is_active() {
            return TestResult::Fail;
        }
        close();
    }
    TestResult::Pass
}

pub(crate) fn test_show_input_dialog() -> TestResult {
    close();
    show_input(b"Input Title", b"Enter value", INPUT_CB_FM_NEW_FOLDER);

    if !is_active() {
        return TestResult::Fail;
    }
    if !is_input_dialog() {
        return TestResult::Fail;
    }
    if get_input_callback() != INPUT_CB_FM_NEW_FOLDER {
        return TestResult::Fail;
    }

    close();
    if is_active() {
        return TestResult::Fail;
    }
    if is_input_dialog() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_input_push_char() -> TestResult {
    close();
    show_input(b"Test", b"Input", INPUT_CB_NONE);

    input_push_char(b'a');
    input_push_char(b'b');
    input_push_char(b'c');

    let text = get_input_text();
    if text != "abc" {
        return TestResult::Fail;
    }

    close();
    TestResult::Pass
}

pub(crate) fn test_input_pop_char() -> TestResult {
    close();
    show_input(b"Test", b"Input", INPUT_CB_NONE);

    input_push_char(b'x');
    input_push_char(b'y');
    input_push_char(b'z');
    input_pop_char();

    let text = get_input_text();
    if text != "xy" {
        return TestResult::Fail;
    }

    close();
    TestResult::Pass
}

pub(crate) fn test_input_pop_char_empty() -> TestResult {
    close();
    show_input(b"Test", b"Input", INPUT_CB_NONE);

    input_pop_char();
    input_pop_char();

    let text = get_input_text();
    if text != "" {
        return TestResult::Fail;
    }

    close();
    TestResult::Pass
}

pub(crate) fn test_close_resets_input() -> TestResult {
    close();
    show_input(b"Test", b"Input", INPUT_CB_FM_RENAME);
    input_push_char(b't');

    close();

    if get_input_callback() != INPUT_CB_NONE {
        return TestResult::Fail;
    }

    close();
    TestResult::Pass
}

pub(crate) fn test_input_max_length() -> TestResult {
    close();
    show_input(b"Test", b"Input", INPUT_CB_NONE);

    for _ in 0..(MAX_INPUT_LEN + 10) {
        input_push_char(b'x');
    }

    let text = get_input_text();
    if !(text.len() < MAX_INPUT_LEN) {
        return TestResult::Fail;
    }

    close();
    TestResult::Pass
}

pub(crate) fn test_dialog_truncates_long_title() -> TestResult {
    close();
    let long_title = [b'T'; 100];
    show_dialog(DIALOG_INFO, &long_title, b"Msg");
    if !is_active() {
        return TestResult::Fail;
    }
    close();
    TestResult::Pass
}

pub(crate) fn test_dialog_truncates_long_message() -> TestResult {
    close();
    let long_msg = [b'M'; 500];
    show_dialog(DIALOG_INFO, b"Title", &long_msg);
    if !is_active() {
        return TestResult::Fail;
    }
    close();
    TestResult::Pass
}

pub(crate) fn test_dialog_empty_title() -> TestResult {
    close();
    show_dialog(DIALOG_INFO, b"", b"Message");
    if !is_active() {
        return TestResult::Fail;
    }
    close();
    TestResult::Pass
}

pub(crate) fn test_dialog_empty_message() -> TestResult {
    close();
    show_dialog(DIALOG_INFO, b"Title", b"");
    if !is_active() {
        return TestResult::Fail;
    }
    close();
    TestResult::Pass
}
