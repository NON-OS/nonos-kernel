// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for agents/tools/mod.rs

use crate::agents::tools::{execute_tool, list_tools, register_tool, MAX_TOOLS};
use crate::test::framework::TestResult;
use alloc::vec::Vec;

fn dummy_tool(_args: &[u8]) -> Vec<u8> {
    b"dummy result".to_vec()
}

fn echo_tool(args: &[u8]) -> Vec<u8> {
    args.to_vec()
}

fn upper_tool(args: &[u8]) -> Vec<u8> {
    args.iter().map(|&c| c.to_ascii_uppercase()).collect()
}

pub(crate) fn test_register_tool() -> TestResult {
    let result = register_tool(b"test_tool_1", b"A test tool", dummy_tool);
    if !result {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_register_tool_with_description() -> TestResult {
    let result =
        register_tool(b"test_tool_2", b"This is a longer description for the tool", dummy_tool);
    if !result {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_execute_tool() -> TestResult {
    register_tool(b"exec_test_tool", b"Exec test", dummy_tool);

    let result = execute_tool(b"exec_test_tool", b"");
    if result.as_slice() != b"dummy result" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_execute_tool_with_args() -> TestResult {
    register_tool(b"echo_tool", b"Echoes input", echo_tool);

    let result = execute_tool(b"echo_tool", b"hello world");
    if result.as_slice() != b"hello world" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_execute_tool_not_found() -> TestResult {
    let result = execute_tool(b"nonexistent_tool_xyz", b"");
    if result.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_execute_tool_transformation() -> TestResult {
    register_tool(b"upper_tool", b"Converts to uppercase", upper_tool);

    let result = execute_tool(b"upper_tool", b"hello");
    if result.as_slice() != b"HELLO" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_list_tools() -> TestResult {
    register_tool(b"list_test_tool", b"For listing test", dummy_tool);

    let tools = list_tools();
    if tools.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_list_tools_contains_registered() -> TestResult {
    register_tool(b"findme_tool", b"Find me desc", dummy_tool);

    let tools = list_tools();
    let found = tools.iter().any(|(name, _)| {
        let len = name.iter().position(|&c| c == 0).unwrap_or(32);
        &name[..len] == b"findme_tool"
    });
    if !found {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_tools_constant() -> TestResult {
    if MAX_TOOLS != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tool_name_truncation() -> TestResult {
    let long_name = [b'x'; 64];
    let result = register_tool(&long_name, b"Long name tool", dummy_tool);
    if !result {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tool_description_truncation() -> TestResult {
    let long_desc = [b'y'; 256];
    let result = register_tool(b"long_desc_tool", &long_desc, dummy_tool);
    if !result {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_execute_empty_args() -> TestResult {
    register_tool(b"empty_args_tool", b"Empty args", echo_tool);

    let result = execute_tool(b"empty_args_tool", b"");
    if !result.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_execute_large_args() -> TestResult {
    register_tool(b"large_args_tool", b"Large args", echo_tool);

    let large_args = [b'z'; 10000];
    let result = execute_tool(b"large_args_tool", &large_args);
    if result.len() != 10000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tool_binary_args() -> TestResult {
    register_tool(b"binary_tool", b"Binary", echo_tool);

    let binary_args = b"\x00\x01\x02\xff\xfe";
    let result = execute_tool(b"binary_tool", binary_args);
    if result.as_slice() != binary_args {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiple_tools() -> TestResult {
    fn tool_a(_: &[u8]) -> Vec<u8> {
        b"A".to_vec()
    }
    fn tool_b(_: &[u8]) -> Vec<u8> {
        b"B".to_vec()
    }
    fn tool_c(_: &[u8]) -> Vec<u8> {
        b"C".to_vec()
    }

    register_tool(b"multi_a", b"Tool A", tool_a);
    register_tool(b"multi_b", b"Tool B", tool_b);
    register_tool(b"multi_c", b"Tool C", tool_c);

    if execute_tool(b"multi_a", b"").as_slice() != b"A" {
        return TestResult::Fail;
    }
    if execute_tool(b"multi_b", b"").as_slice() != b"B" {
        return TestResult::Fail;
    }
    if execute_tool(b"multi_c", b"").as_slice() != b"C" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tool_returns_empty() -> TestResult {
    fn empty_tool(_: &[u8]) -> Vec<u8> {
        Vec::new()
    }

    register_tool(b"empty_return_tool", b"Returns empty", empty_tool);

    let result = execute_tool(b"empty_return_tool", b"data");
    if !result.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_list_tools_name_and_description() -> TestResult {
    register_tool(b"info_tool", b"Info description", dummy_tool);

    let tools = list_tools();
    let found = tools.iter().find(|(name, _)| {
        let len = name.iter().position(|&c| c == 0).unwrap_or(32);
        &name[..len] == b"info_tool"
    });

    if found.is_none() {
        return TestResult::Fail;
    }
    let (_, desc) = found.unwrap();
    let desc_len = desc.iter().position(|&c| c == 0).unwrap_or(128);
    if &desc[..desc_len] != b"Info description" {
        return TestResult::Fail;
    }
    TestResult::Pass
}
