// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for agents/context.rs - AgentContext

use crate::agents::context::AgentContext;

#[test_case]
fn test_context_new() {
    let ctx = AgentContext::new(1);

    assert_eq!(ctx.agent_id, 1);
    assert_eq!(ctx.working_dir.as_slice(), b"/ram");
    assert!(ctx.env_vars.is_empty());
    assert!(ctx.history.is_empty());
    assert_eq!(ctx.active_tools, [false; 16]);
}

#[test_case]
fn test_context_new_different_ids() {
    let ctx1 = AgentContext::new(1);
    let ctx2 = AgentContext::new(42);
    let ctx3 = AgentContext::new(999);

    assert_eq!(ctx1.agent_id, 1);
    assert_eq!(ctx2.agent_id, 42);
    assert_eq!(ctx3.agent_id, 999);
}

#[test_case]
fn test_context_set_env_new_key() {
    let mut ctx = AgentContext::new(1);

    ctx.set_env(b"PATH", b"/bin:/usr/bin");

    assert_eq!(ctx.env_vars.len(), 1);
    assert_eq!(ctx.env_vars[0].0.as_slice(), b"PATH");
    assert_eq!(ctx.env_vars[0].1.as_slice(), b"/bin:/usr/bin");
}

#[test_case]
fn test_context_set_env_update_existing() {
    let mut ctx = AgentContext::new(1);

    ctx.set_env(b"PATH", b"/bin");
    ctx.set_env(b"PATH", b"/usr/bin");

    // Should update, not add new
    assert_eq!(ctx.env_vars.len(), 1);
    assert_eq!(ctx.env_vars[0].1.as_slice(), b"/usr/bin");
}

#[test_case]
fn test_context_set_env_multiple_keys() {
    let mut ctx = AgentContext::new(1);

    ctx.set_env(b"PATH", b"/bin");
    ctx.set_env(b"HOME", b"/home/user");
    ctx.set_env(b"SHELL", b"/bin/bash");

    assert_eq!(ctx.env_vars.len(), 3);
}

#[test_case]
fn test_context_get_env_existing() {
    let mut ctx = AgentContext::new(1);
    ctx.set_env(b"TEST_VAR", b"test_value");

    let value = ctx.get_env(b"TEST_VAR");
    assert!(value.is_some());
    assert_eq!(value.unwrap(), b"test_value");
}

#[test_case]
fn test_context_get_env_nonexistent() {
    let ctx = AgentContext::new(1);

    let value = ctx.get_env(b"NONEXISTENT");
    assert!(value.is_none());
}

#[test_case]
fn test_context_get_env_empty_value() {
    let mut ctx = AgentContext::new(1);
    ctx.set_env(b"EMPTY", b"");

    let value = ctx.get_env(b"EMPTY");
    assert!(value.is_some());
    assert!(value.unwrap().is_empty());
}

#[test_case]
fn test_context_add_history() {
    let mut ctx = AgentContext::new(1);

    ctx.add_history(b"command1");
    ctx.add_history(b"command2");
    ctx.add_history(b"command3");

    assert_eq!(ctx.history.len(), 3);
    assert_eq!(ctx.history[0].as_slice(), b"command1");
    assert_eq!(ctx.history[1].as_slice(), b"command2");
    assert_eq!(ctx.history[2].as_slice(), b"command3");
}

#[test_case]
fn test_context_history_limit() {
    let mut ctx = AgentContext::new(1);

    // Add 101 entries (limit is 100)
    for i in 0..101 {
        ctx.add_history(&[i as u8]);
    }

    // Should only keep 100 entries
    assert_eq!(ctx.history.len(), 100);
    // First entry should be removed
    assert_eq!(ctx.history[0].as_slice(), &[1u8]);
    // Last entry should be the newest
    assert_eq!(ctx.history[99].as_slice(), &[100u8]);
}

#[test_case]
fn test_context_history_fifo_eviction() {
    let mut ctx = AgentContext::new(1);

    // Fill to capacity
    for i in 0..100 {
        ctx.add_history(&[i as u8]);
    }
    assert_eq!(ctx.history.len(), 100);
    assert_eq!(ctx.history[0].as_slice(), &[0u8]);

    // Add one more
    ctx.add_history(b"new");
    assert_eq!(ctx.history.len(), 100);
    assert_eq!(ctx.history[0].as_slice(), &[1u8]); // 0 was evicted
    assert_eq!(ctx.history[99].as_slice(), b"new");
}

#[test_case]
fn test_context_enable_tool() {
    let mut ctx = AgentContext::new(1);

    assert!(!ctx.active_tools[0]);
    ctx.enable_tool(0);
    assert!(ctx.active_tools[0]);

    ctx.enable_tool(5);
    assert!(ctx.active_tools[5]);

    ctx.enable_tool(15);
    assert!(ctx.active_tools[15]);
}

#[test_case]
fn test_context_enable_tool_out_of_bounds() {
    let mut ctx = AgentContext::new(1);

    // Should not panic for out-of-bounds index
    ctx.enable_tool(16);
    ctx.enable_tool(100);
    ctx.enable_tool(usize::MAX);

    // All tools should still be disabled
    for i in 0..16 {
        assert!(!ctx.active_tools[i]);
    }
}

#[test_case]
fn test_context_disable_tool() {
    let mut ctx = AgentContext::new(1);

    ctx.enable_tool(5);
    assert!(ctx.active_tools[5]);

    ctx.disable_tool(5);
    assert!(!ctx.active_tools[5]);
}

#[test_case]
fn test_context_disable_tool_out_of_bounds() {
    let mut ctx = AgentContext::new(1);
    ctx.enable_tool(0);

    // Should not panic for out-of-bounds index
    ctx.disable_tool(16);
    ctx.disable_tool(100);

    // Tool 0 should still be enabled
    assert!(ctx.active_tools[0]);
}

#[test_case]
fn test_context_is_tool_enabled() {
    let mut ctx = AgentContext::new(1);

    assert!(!ctx.is_tool_enabled(0));
    ctx.enable_tool(0);
    assert!(ctx.is_tool_enabled(0));

    ctx.disable_tool(0);
    assert!(!ctx.is_tool_enabled(0));
}

#[test_case]
fn test_context_is_tool_enabled_out_of_bounds() {
    let ctx = AgentContext::new(1);

    // Out of bounds should return false
    assert!(!ctx.is_tool_enabled(16));
    assert!(!ctx.is_tool_enabled(100));
    assert!(!ctx.is_tool_enabled(usize::MAX));
}

#[test_case]
fn test_context_multiple_tools() {
    let mut ctx = AgentContext::new(1);

    ctx.enable_tool(0);
    ctx.enable_tool(3);
    ctx.enable_tool(7);
    ctx.enable_tool(15);

    assert!(ctx.is_tool_enabled(0));
    assert!(!ctx.is_tool_enabled(1));
    assert!(!ctx.is_tool_enabled(2));
    assert!(ctx.is_tool_enabled(3));
    assert!(!ctx.is_tool_enabled(4));
    assert!(ctx.is_tool_enabled(7));
    assert!(ctx.is_tool_enabled(15));

    let enabled_count = ctx.active_tools.iter().filter(|&&x| x).count();
    assert_eq!(enabled_count, 4);
}

#[test_case]
fn test_context_clone() {
    let mut ctx = AgentContext::new(1);
    ctx.set_env(b"KEY", b"VALUE");
    ctx.add_history(b"cmd");
    ctx.enable_tool(5);

    let cloned = ctx.clone();
    assert_eq!(cloned.agent_id, 1);
    assert_eq!(cloned.env_vars.len(), 1);
    assert_eq!(cloned.history.len(), 1);
    assert!(cloned.is_tool_enabled(5));
}

#[test_case]
fn test_context_working_dir_default() {
    let ctx = AgentContext::new(1);
    assert_eq!(ctx.working_dir.as_slice(), b"/ram");
}

#[test_case]
fn test_context_working_dir_modification() {
    let mut ctx = AgentContext::new(1);
    ctx.working_dir = b"/home/user".to_vec();
    assert_eq!(ctx.working_dir.as_slice(), b"/home/user");
}

#[test_case]
fn test_context_env_binary_values() {
    let mut ctx = AgentContext::new(1);

    // Test with binary data containing null bytes
    let binary_key = b"BIN_KEY\0TEST";
    let binary_value = b"\x00\x01\x02\x03";

    ctx.set_env(binary_key, binary_value);
    let retrieved = ctx.get_env(binary_key);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap(), binary_value);
}
