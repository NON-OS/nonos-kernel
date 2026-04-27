// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::shell::commands::pipeline::{Pipeline, RedirectType};
use crate::test::framework::TestResult;

pub(crate) fn test_redirect_type_none() -> TestResult {
    let rt = RedirectType::None;
    if rt != RedirectType::None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_redirect_type_write() -> TestResult {
    let rt = RedirectType::Write;
    if rt != RedirectType::Write {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_redirect_type_append() -> TestResult {
    let rt = RedirectType::Append;
    if rt != RedirectType::Append {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_redirect_type_input() -> TestResult {
    let rt = RedirectType::Input;
    if rt != RedirectType::Input {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_redirect_type_equality() -> TestResult {
    if RedirectType::None != RedirectType::None {
        return TestResult::Fail;
    }
    if RedirectType::None == RedirectType::Write {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_parse_simple() -> TestResult {
    let pipe = Pipeline::parse(b"ls");
    if pipe.stages.len() != 1 {
        return TestResult::Fail;
    }
    if pipe.stages[0].command != b"ls" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_parse_with_args() -> TestResult {
    let pipe = Pipeline::parse(b"ls -la /home");
    if pipe.stages.len() != 1 {
        return TestResult::Fail;
    }
    if pipe.stages[0].command != b"ls -la /home" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_parse_two_stages() -> TestResult {
    let pipe = Pipeline::parse(b"ls | grep txt");
    if pipe.stages.len() != 2 {
        return TestResult::Fail;
    }
    if pipe.stages[0].command != b"ls" {
        return TestResult::Fail;
    }
    if pipe.stages[1].command != b"grep txt" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_parse_three_stages() -> TestResult {
    let pipe = Pipeline::parse(b"cat file | grep pattern | wc -l");
    if pipe.stages.len() != 3 {
        return TestResult::Fail;
    }
    if pipe.stages[0].command != b"cat file" {
        return TestResult::Fail;
    }
    if pipe.stages[1].command != b"grep pattern" {
        return TestResult::Fail;
    }
    if pipe.stages[2].command != b"wc -l" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_parse_redirect_write() -> TestResult {
    let pipe = Pipeline::parse(b"ls > output.txt");
    if pipe.stages.len() != 1 {
        return TestResult::Fail;
    }
    if pipe.stages[0].command != b"ls" {
        return TestResult::Fail;
    }
    if pipe.stages[0].redirect_type != RedirectType::Write {
        return TestResult::Fail;
    }
    if pipe.stages[0].redirect_target != Some(b"output.txt" as &[u8]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_parse_redirect_append() -> TestResult {
    let pipe = Pipeline::parse(b"echo hello >> log.txt");
    if pipe.stages.len() != 1 {
        return TestResult::Fail;
    }
    if pipe.stages[0].command != b"echo hello" {
        return TestResult::Fail;
    }
    if pipe.stages[0].redirect_type != RedirectType::Append {
        return TestResult::Fail;
    }
    if pipe.stages[0].redirect_target != Some(b"log.txt" as &[u8]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_parse_redirect_input() -> TestResult {
    let pipe = Pipeline::parse(b"cat < input.txt");
    if pipe.stages.len() != 1 {
        return TestResult::Fail;
    }
    if pipe.stages[0].command != b"cat" {
        return TestResult::Fail;
    }
    if pipe.stages[0].redirect_type != RedirectType::Input {
        return TestResult::Fail;
    }
    if pipe.stages[0].redirect_target != Some(b"input.txt" as &[u8]) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_is_simple_true() -> TestResult {
    let pipe = Pipeline::parse(b"ls");
    if !pipe.is_simple() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_is_simple_false_with_pipe() -> TestResult {
    let pipe = Pipeline::parse(b"ls | grep x");
    if pipe.is_simple() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_is_simple_false_with_redirect() -> TestResult {
    let pipe = Pipeline::parse(b"ls > file");
    if pipe.is_simple() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_has_pipes_false() -> TestResult {
    let pipe = Pipeline::parse(b"ls");
    if pipe.has_pipes() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_has_pipes_true() -> TestResult {
    let pipe = Pipeline::parse(b"ls | wc");
    if !pipe.has_pipes() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_parse_empty() -> TestResult {
    let pipe = Pipeline::parse(b"");
    if pipe.stages.len() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_parse_whitespace_only() -> TestResult {
    let pipe = Pipeline::parse(b"   ");
    if pipe.stages.len() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_parse_trims_whitespace() -> TestResult {
    let pipe = Pipeline::parse(b"  ls  ");
    if pipe.stages.len() != 1 {
        return TestResult::Fail;
    }
    if pipe.stages[0].command != b"ls" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_parse_pipe_with_spaces() -> TestResult {
    let pipe = Pipeline::parse(b"ls  |  grep x");
    if pipe.stages.len() != 2 {
        return TestResult::Fail;
    }
    if pipe.stages[0].command != b"ls" {
        return TestResult::Fail;
    }
    if pipe.stages[1].command != b"grep x" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_parse_redirect_no_target() -> TestResult {
    let pipe = Pipeline::parse(b"ls >");
    if pipe.stages.len() != 1 {
        return TestResult::Fail;
    }
    if pipe.stages[0].redirect_type != RedirectType::Write {
        return TestResult::Fail;
    }
    if pipe.stages[0].redirect_target.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_parse_multiple_pipes_and_redirect() -> TestResult {
    let pipe = Pipeline::parse(b"cat file | grep x | sort > out");
    if pipe.stages.len() != 3 {
        return TestResult::Fail;
    }
    if pipe.stages[2].redirect_type != RedirectType::Write {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_stage_command_preserved() -> TestResult {
    let pipe = Pipeline::parse(b"echo 'hello world'");
    if pipe.stages[0].command != b"echo 'hello world'" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_redirect_type_copy() -> TestResult {
    let rt1 = RedirectType::Write;
    let rt2 = rt1;
    if rt2 != RedirectType::Write {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_redirect_type_clone() -> TestResult {
    let rt = RedirectType::Append;
    let cloned = rt.clone();
    if cloned != RedirectType::Append {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_parse_long_command() -> TestResult {
    let long_cmd = b"very_long_command_name with many arguments and options";
    let pipe = Pipeline::parse(long_cmd);
    if pipe.stages.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pipeline_parse_tabs() -> TestResult {
    let pipe = Pipeline::parse(b"ls\t|\tgrep x");
    if pipe.stages.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
