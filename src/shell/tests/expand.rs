// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::shell::commands::expand::expand_variables;
use crate::test::framework::TestResult;

pub(crate) fn test_expand_no_variables() -> TestResult {
    let result = expand_variables(b"ls -la");
    if result.as_slice() != b"ls -la" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_empty() -> TestResult {
    let result = expand_variables(b"");
    if result.as_slice() != b"" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_dollar_sign_alone() -> TestResult {
    let result = expand_variables(b"echo $");
    if result.as_slice() != b"echo $" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_exit_status() -> TestResult {
    let result = expand_variables(b"echo $?");
    if result.as_slice() != b"echo 0" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_pid() -> TestResult {
    let result = expand_variables(b"echo $$");
    if result.len() < 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_text_without_vars() -> TestResult {
    let result = expand_variables(b"hello world");
    if result.as_slice() != b"hello world" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_preserves_spaces() -> TestResult {
    let result = expand_variables(b"echo   hello   world");
    if result.as_slice() != b"echo   hello   world" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_preserves_special_chars() -> TestResult {
    let result = expand_variables(b"echo @#%^&*()");
    if result.as_slice() != b"echo @#%^&*()" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_braced_var_missing_close() -> TestResult {
    let result = expand_variables(b"echo ${VAR");
    if result.len() <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_multiple_dollar_signs() -> TestResult {
    let result = expand_variables(b"$$ $$ $$");
    if result.len() <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_mixed_content() -> TestResult {
    let result = expand_variables(b"prefix $? suffix");
    if !result.starts_with(b"prefix ") {
        return TestResult::Fail;
    }
    if !result.ends_with(b" suffix") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_consecutive_vars() -> TestResult {
    let result = expand_variables(b"$?$?");
    if result.as_slice() != b"00" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_var_at_start() -> TestResult {
    let result = expand_variables(b"$? is status");
    if !result.starts_with(b"0") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_var_at_end() -> TestResult {
    let result = expand_variables(b"status is $?");
    if !result.ends_with(b"0") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_dollar_number() -> TestResult {
    let result = expand_variables(b"echo $1");
    if result.len() < 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_preserves_quotes() -> TestResult {
    let result = expand_variables(b"echo 'hello'");
    if result.as_slice() != b"echo 'hello'" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_preserves_double_quotes() -> TestResult {
    let result = expand_variables(b"echo \"hello\"");
    if result.as_slice() != b"echo \"hello\"" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_preserves_backslash() -> TestResult {
    let result = expand_variables(b"echo \\n");
    if result.as_slice() != b"echo \\n" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_long_input() -> TestResult {
    let long_input = [b'a'; 500];
    let result = expand_variables(&long_input);
    if result.len() > 512 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_newlines() -> TestResult {
    let result = expand_variables(b"echo\nhello");
    if result.as_slice() != b"echo\nhello" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_tabs() -> TestResult {
    let result = expand_variables(b"echo\thello");
    if result.as_slice() != b"echo\thello" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_expand_unicode_bytes() -> TestResult {
    let result = expand_variables(b"echo \xc3\xa9");
    if result.as_slice() != b"echo \xc3\xa9" {
        return TestResult::Fail;
    }
    TestResult::Pass
}
