use crate::shell::commands::pipeline::{Pipeline, RedirectType};

#[test]
fn test_redirect_type_none() {
    let rt = RedirectType::None;
    assert_eq!(rt, RedirectType::None);
}

#[test]
fn test_redirect_type_write() {
    let rt = RedirectType::Write;
    assert_eq!(rt, RedirectType::Write);
}

#[test]
fn test_redirect_type_append() {
    let rt = RedirectType::Append;
    assert_eq!(rt, RedirectType::Append);
}

#[test]
fn test_redirect_type_input() {
    let rt = RedirectType::Input;
    assert_eq!(rt, RedirectType::Input);
}

#[test]
fn test_redirect_type_equality() {
    assert_eq!(RedirectType::None, RedirectType::None);
    assert_ne!(RedirectType::None, RedirectType::Write);
}

#[test]
fn test_pipeline_parse_simple() {
    let pipe = Pipeline::parse(b"ls");
    assert_eq!(pipe.stages.len(), 1);
    assert_eq!(pipe.stages[0].command, b"ls");
}

#[test]
fn test_pipeline_parse_with_args() {
    let pipe = Pipeline::parse(b"ls -la /home");
    assert_eq!(pipe.stages.len(), 1);
    assert_eq!(pipe.stages[0].command, b"ls -la /home");
}

#[test]
fn test_pipeline_parse_two_stages() {
    let pipe = Pipeline::parse(b"ls | grep txt");
    assert_eq!(pipe.stages.len(), 2);
    assert_eq!(pipe.stages[0].command, b"ls");
    assert_eq!(pipe.stages[1].command, b"grep txt");
}

#[test]
fn test_pipeline_parse_three_stages() {
    let pipe = Pipeline::parse(b"cat file | grep pattern | wc -l");
    assert_eq!(pipe.stages.len(), 3);
    assert_eq!(pipe.stages[0].command, b"cat file");
    assert_eq!(pipe.stages[1].command, b"grep pattern");
    assert_eq!(pipe.stages[2].command, b"wc -l");
}

#[test]
fn test_pipeline_parse_redirect_write() {
    let pipe = Pipeline::parse(b"ls > output.txt");
    assert_eq!(pipe.stages.len(), 1);
    assert_eq!(pipe.stages[0].command, b"ls");
    assert_eq!(pipe.stages[0].redirect_type, RedirectType::Write);
    assert_eq!(pipe.stages[0].redirect_target, Some(b"output.txt" as &[u8]));
}

#[test]
fn test_pipeline_parse_redirect_append() {
    let pipe = Pipeline::parse(b"echo hello >> log.txt");
    assert_eq!(pipe.stages.len(), 1);
    assert_eq!(pipe.stages[0].command, b"echo hello");
    assert_eq!(pipe.stages[0].redirect_type, RedirectType::Append);
    assert_eq!(pipe.stages[0].redirect_target, Some(b"log.txt" as &[u8]));
}

#[test]
fn test_pipeline_parse_redirect_input() {
    let pipe = Pipeline::parse(b"cat < input.txt");
    assert_eq!(pipe.stages.len(), 1);
    assert_eq!(pipe.stages[0].command, b"cat");
    assert_eq!(pipe.stages[0].redirect_type, RedirectType::Input);
    assert_eq!(pipe.stages[0].redirect_target, Some(b"input.txt" as &[u8]));
}

#[test]
fn test_pipeline_is_simple_true() {
    let pipe = Pipeline::parse(b"ls");
    assert!(pipe.is_simple());
}

#[test]
fn test_pipeline_is_simple_false_with_pipe() {
    let pipe = Pipeline::parse(b"ls | grep x");
    assert!(!pipe.is_simple());
}

#[test]
fn test_pipeline_is_simple_false_with_redirect() {
    let pipe = Pipeline::parse(b"ls > file");
    assert!(!pipe.is_simple());
}

#[test]
fn test_pipeline_has_pipes_false() {
    let pipe = Pipeline::parse(b"ls");
    assert!(!pipe.has_pipes());
}

#[test]
fn test_pipeline_has_pipes_true() {
    let pipe = Pipeline::parse(b"ls | wc");
    assert!(pipe.has_pipes());
}

#[test]
fn test_pipeline_parse_empty() {
    let pipe = Pipeline::parse(b"");
    assert_eq!(pipe.stages.len(), 0);
}

#[test]
fn test_pipeline_parse_whitespace_only() {
    let pipe = Pipeline::parse(b"   ");
    assert_eq!(pipe.stages.len(), 0);
}

#[test]
fn test_pipeline_parse_trims_whitespace() {
    let pipe = Pipeline::parse(b"  ls  ");
    assert_eq!(pipe.stages.len(), 1);
    assert_eq!(pipe.stages[0].command, b"ls");
}

#[test]
fn test_pipeline_parse_pipe_with_spaces() {
    let pipe = Pipeline::parse(b"ls  |  grep x");
    assert_eq!(pipe.stages.len(), 2);
    assert_eq!(pipe.stages[0].command, b"ls");
    assert_eq!(pipe.stages[1].command, b"grep x");
}

#[test]
fn test_pipeline_parse_redirect_no_target() {
    let pipe = Pipeline::parse(b"ls >");
    assert_eq!(pipe.stages.len(), 1);
    assert_eq!(pipe.stages[0].redirect_type, RedirectType::Write);
    assert!(pipe.stages[0].redirect_target.is_none());
}

#[test]
fn test_pipeline_parse_multiple_pipes_and_redirect() {
    let pipe = Pipeline::parse(b"cat file | grep x | sort > out");
    assert_eq!(pipe.stages.len(), 3);
    assert_eq!(pipe.stages[2].redirect_type, RedirectType::Write);
}

#[test]
fn test_pipeline_stage_command_preserved() {
    let pipe = Pipeline::parse(b"echo 'hello world'");
    assert_eq!(pipe.stages[0].command, b"echo 'hello world'");
}

#[test]
fn test_pipeline_redirect_type_copy() {
    let rt1 = RedirectType::Write;
    let rt2 = rt1;
    assert_eq!(rt2, RedirectType::Write);
}

#[test]
fn test_pipeline_redirect_type_clone() {
    let rt = RedirectType::Append;
    let cloned = rt.clone();
    assert_eq!(cloned, RedirectType::Append);
}

#[test]
fn test_pipeline_parse_long_command() {
    let long_cmd = b"very_long_command_name with many arguments and options";
    let pipe = Pipeline::parse(long_cmd);
    assert_eq!(pipe.stages.len(), 1);
}

#[test]
fn test_pipeline_parse_tabs() {
    let pipe = Pipeline::parse(b"ls\t|\tgrep x");
    assert_eq!(pipe.stages.len(), 2);
}
