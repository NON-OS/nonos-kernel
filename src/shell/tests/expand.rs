use crate::shell::commands::expand::expand_variables;

#[test]
fn test_expand_no_variables() {
    let result = expand_variables(b"ls -la");
    assert_eq!(result.as_slice(), b"ls -la");
}

#[test]
fn test_expand_empty() {
    let result = expand_variables(b"");
    assert_eq!(result.as_slice(), b"");
}

#[test]
fn test_expand_dollar_sign_alone() {
    let result = expand_variables(b"echo $");
    assert_eq!(result.as_slice(), b"echo $");
}

#[test]
fn test_expand_exit_status() {
    let result = expand_variables(b"echo $?");
    assert_eq!(result.as_slice(), b"echo 0");
}

#[test]
fn test_expand_pid() {
    let result = expand_variables(b"echo $$");
    assert!(result.len() >= 6);
}

#[test]
fn test_expand_text_without_vars() {
    let result = expand_variables(b"hello world");
    assert_eq!(result.as_slice(), b"hello world");
}

#[test]
fn test_expand_preserves_spaces() {
    let result = expand_variables(b"echo   hello   world");
    assert_eq!(result.as_slice(), b"echo   hello   world");
}

#[test]
fn test_expand_preserves_special_chars() {
    let result = expand_variables(b"echo @#%^&*()");
    assert_eq!(result.as_slice(), b"echo @#%^&*()");
}

#[test]
fn test_expand_braced_var_missing_close() {
    let result = expand_variables(b"echo ${VAR");
    assert!(result.len() > 0);
}

#[test]
fn test_expand_multiple_dollar_signs() {
    let result = expand_variables(b"$$ $$ $$");
    assert!(result.len() > 0);
}

#[test]
fn test_expand_mixed_content() {
    let result = expand_variables(b"prefix $? suffix");
    assert!(result.starts_with(b"prefix "));
    assert!(result.ends_with(b" suffix"));
}

#[test]
fn test_expand_consecutive_vars() {
    let result = expand_variables(b"$?$?");
    assert_eq!(result.as_slice(), b"00");
}

#[test]
fn test_expand_var_at_start() {
    let result = expand_variables(b"$? is status");
    assert!(result.starts_with(b"0"));
}

#[test]
fn test_expand_var_at_end() {
    let result = expand_variables(b"status is $?");
    assert!(result.ends_with(b"0"));
}

#[test]
fn test_expand_dollar_number() {
    let result = expand_variables(b"echo $1");
    assert!(result.len() >= 6);
}

#[test]
fn test_expand_preserves_quotes() {
    let result = expand_variables(b"echo 'hello'");
    assert_eq!(result.as_slice(), b"echo 'hello'");
}

#[test]
fn test_expand_preserves_double_quotes() {
    let result = expand_variables(b"echo \"hello\"");
    assert_eq!(result.as_slice(), b"echo \"hello\"");
}

#[test]
fn test_expand_preserves_backslash() {
    let result = expand_variables(b"echo \\n");
    assert_eq!(result.as_slice(), b"echo \\n");
}

#[test]
fn test_expand_long_input() {
    let long_input = [b'a'; 500];
    let result = expand_variables(&long_input);
    assert!(result.len() <= 512);
}

#[test]
fn test_expand_newlines() {
    let result = expand_variables(b"echo\nhello");
    assert_eq!(result.as_slice(), b"echo\nhello");
}

#[test]
fn test_expand_tabs() {
    let result = expand_variables(b"echo\thello");
    assert_eq!(result.as_slice(), b"echo\thello");
}

#[test]
fn test_expand_unicode_bytes() {
    let result = expand_variables(b"echo \xc3\xa9");
    assert_eq!(result.as_slice(), b"echo \xc3\xa9");
}
