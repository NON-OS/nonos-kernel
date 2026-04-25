// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for agents/context.rs - AgentContext

use crate::agents::context::AgentContext;
use crate::test::framework::TestResult;

pub(crate) fn test_context_new() -> TestResult {
    let ctx = AgentContext::new(1);

    if ctx.agent_id != 1 {
        return TestResult::Fail;
    }
    if ctx.working_dir.as_slice() != b"/ram" {
        return TestResult::Fail;
    }
    if !ctx.env_vars.is_empty() {
        return TestResult::Fail;
    }
    if !ctx.history.is_empty() {
        return TestResult::Fail;
    }
    if ctx.active_tools != [false; 16] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_new_different_ids() -> TestResult {
    let ctx1 = AgentContext::new(1);
    let ctx2 = AgentContext::new(42);
    let ctx3 = AgentContext::new(999);

    if ctx1.agent_id != 1 {
        return TestResult::Fail;
    }
    if ctx2.agent_id != 42 {
        return TestResult::Fail;
    }
    if ctx3.agent_id != 999 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_set_env_new_key() -> TestResult {
    let mut ctx = AgentContext::new(1);

    ctx.set_env(b"PATH", b"/bin:/usr/bin");

    if ctx.env_vars.len() != 1 {
        return TestResult::Fail;
    }
    if ctx.env_vars[0].0.as_slice() != b"PATH" {
        return TestResult::Fail;
    }
    if ctx.env_vars[0].1.as_slice() != b"/bin:/usr/bin" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_set_env_update_existing() -> TestResult {
    let mut ctx = AgentContext::new(1);

    ctx.set_env(b"PATH", b"/bin");
    ctx.set_env(b"PATH", b"/usr/bin");

    if ctx.env_vars.len() != 1 {
        return TestResult::Fail;
    }
    if ctx.env_vars[0].1.as_slice() != b"/usr/bin" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_set_env_multiple_keys() -> TestResult {
    let mut ctx = AgentContext::new(1);

    ctx.set_env(b"PATH", b"/bin");
    ctx.set_env(b"HOME", b"/home/user");
    ctx.set_env(b"SHELL", b"/bin/bash");

    if ctx.env_vars.len() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_get_env_existing() -> TestResult {
    let mut ctx = AgentContext::new(1);
    ctx.set_env(b"TEST_VAR", b"test_value");

    let value = ctx.get_env(b"TEST_VAR");
    if value.is_none() {
        return TestResult::Fail;
    }
    if value.unwrap() != b"test_value" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_get_env_nonexistent() -> TestResult {
    let ctx = AgentContext::new(1);

    let value = ctx.get_env(b"NONEXISTENT");
    if value.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_get_env_empty_value() -> TestResult {
    let mut ctx = AgentContext::new(1);
    ctx.set_env(b"EMPTY", b"");

    let value = ctx.get_env(b"EMPTY");
    if value.is_none() {
        return TestResult::Fail;
    }
    if !value.unwrap().is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_add_history() -> TestResult {
    let mut ctx = AgentContext::new(1);

    ctx.add_history(b"command1");
    ctx.add_history(b"command2");
    ctx.add_history(b"command3");

    if ctx.history.len() != 3 {
        return TestResult::Fail;
    }
    if ctx.history[0].as_slice() != b"command1" {
        return TestResult::Fail;
    }
    if ctx.history[1].as_slice() != b"command2" {
        return TestResult::Fail;
    }
    if ctx.history[2].as_slice() != b"command3" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_history_limit() -> TestResult {
    let mut ctx = AgentContext::new(1);

    for i in 0..101 {
        ctx.add_history(&[i as u8]);
    }

    if ctx.history.len() != 100 {
        return TestResult::Fail;
    }
    if ctx.history[0].as_slice() != &[1u8] {
        return TestResult::Fail;
    }
    if ctx.history[99].as_slice() != &[100u8] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_history_fifo_eviction() -> TestResult {
    let mut ctx = AgentContext::new(1);

    for i in 0..100 {
        ctx.add_history(&[i as u8]);
    }
    if ctx.history.len() != 100 {
        return TestResult::Fail;
    }
    if ctx.history[0].as_slice() != &[0u8] {
        return TestResult::Fail;
    }

    ctx.add_history(b"new");
    if ctx.history.len() != 100 {
        return TestResult::Fail;
    }
    if ctx.history[0].as_slice() != &[1u8] {
        return TestResult::Fail;
    }
    if ctx.history[99].as_slice() != b"new" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_enable_tool() -> TestResult {
    let mut ctx = AgentContext::new(1);

    if ctx.active_tools[0] {
        return TestResult::Fail;
    }
    ctx.enable_tool(0);
    if !ctx.active_tools[0] {
        return TestResult::Fail;
    }

    ctx.enable_tool(5);
    if !ctx.active_tools[5] {
        return TestResult::Fail;
    }

    ctx.enable_tool(15);
    if !ctx.active_tools[15] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_enable_tool_out_of_bounds() -> TestResult {
    let mut ctx = AgentContext::new(1);

    ctx.enable_tool(16);
    ctx.enable_tool(100);
    ctx.enable_tool(usize::MAX);

    for i in 0..16 {
        if ctx.active_tools[i] {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_context_disable_tool() -> TestResult {
    let mut ctx = AgentContext::new(1);

    ctx.enable_tool(5);
    if !ctx.active_tools[5] {
        return TestResult::Fail;
    }

    ctx.disable_tool(5);
    if ctx.active_tools[5] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_disable_tool_out_of_bounds() -> TestResult {
    let mut ctx = AgentContext::new(1);
    ctx.enable_tool(0);

    ctx.disable_tool(16);
    ctx.disable_tool(100);

    if !ctx.active_tools[0] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_is_tool_enabled() -> TestResult {
    let mut ctx = AgentContext::new(1);

    if ctx.is_tool_enabled(0) {
        return TestResult::Fail;
    }
    ctx.enable_tool(0);
    if !ctx.is_tool_enabled(0) {
        return TestResult::Fail;
    }

    ctx.disable_tool(0);
    if ctx.is_tool_enabled(0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_is_tool_enabled_out_of_bounds() -> TestResult {
    let ctx = AgentContext::new(1);

    if ctx.is_tool_enabled(16) {
        return TestResult::Fail;
    }
    if ctx.is_tool_enabled(100) {
        return TestResult::Fail;
    }
    if ctx.is_tool_enabled(usize::MAX) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_multiple_tools() -> TestResult {
    let mut ctx = AgentContext::new(1);

    ctx.enable_tool(0);
    ctx.enable_tool(3);
    ctx.enable_tool(7);
    ctx.enable_tool(15);

    if !ctx.is_tool_enabled(0) {
        return TestResult::Fail;
    }
    if ctx.is_tool_enabled(1) {
        return TestResult::Fail;
    }
    if ctx.is_tool_enabled(2) {
        return TestResult::Fail;
    }
    if !ctx.is_tool_enabled(3) {
        return TestResult::Fail;
    }
    if ctx.is_tool_enabled(4) {
        return TestResult::Fail;
    }
    if !ctx.is_tool_enabled(7) {
        return TestResult::Fail;
    }
    if !ctx.is_tool_enabled(15) {
        return TestResult::Fail;
    }

    let enabled_count = ctx.active_tools.iter().filter(|&&x| x).count();
    if enabled_count != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_clone() -> TestResult {
    let mut ctx = AgentContext::new(1);
    ctx.set_env(b"KEY", b"VALUE");
    ctx.add_history(b"cmd");
    ctx.enable_tool(5);

    let cloned = ctx.clone();
    if cloned.agent_id != 1 {
        return TestResult::Fail;
    }
    if cloned.env_vars.len() != 1 {
        return TestResult::Fail;
    }
    if cloned.history.len() != 1 {
        return TestResult::Fail;
    }
    if !cloned.is_tool_enabled(5) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_working_dir_default() -> TestResult {
    let ctx = AgentContext::new(1);
    if ctx.working_dir.as_slice() != b"/ram" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_working_dir_modification() -> TestResult {
    let mut ctx = AgentContext::new(1);
    ctx.working_dir = b"/home/user".to_vec();
    if ctx.working_dir.as_slice() != b"/home/user" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_env_binary_values() -> TestResult {
    let mut ctx = AgentContext::new(1);

    let binary_key = b"BIN_KEY\0TEST";
    let binary_value = b"\x00\x01\x02\x03";

    ctx.set_env(binary_key, binary_value);
    let retrieved = ctx.get_env(binary_key);
    if retrieved.is_none() {
        return TestResult::Fail;
    }
    if retrieved.unwrap() != binary_value {
        return TestResult::Fail;
    }
    TestResult::Pass
}
