// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for agents/core.rs - Agent, AgentConfig, AgentState, MessageRole

use crate::agents::core::{Agent, AgentConfig, AgentMessage, AgentState, MessageRole};
use crate::test::framework::TestResult;

pub(crate) fn test_agent_state_variants() -> TestResult {
    if AgentState::Idle != AgentState::Idle {
        return TestResult::Fail;
    }
    if AgentState::Running != AgentState::Running {
        return TestResult::Fail;
    }
    if AgentState::Paused != AgentState::Paused {
        return TestResult::Fail;
    }
    if AgentState::Error != AgentState::Error {
        return TestResult::Fail;
    }
    if AgentState::Complete != AgentState::Complete {
        return TestResult::Fail;
    }
    if AgentState::Idle == AgentState::Running {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_role_variants() -> TestResult {
    if MessageRole::System != MessageRole::System {
        return TestResult::Fail;
    }
    if MessageRole::User != MessageRole::User {
        return TestResult::Fail;
    }
    if MessageRole::Assistant != MessageRole::Assistant {
        return TestResult::Fail;
    }
    if MessageRole::Tool != MessageRole::Tool {
        return TestResult::Fail;
    }
    if MessageRole::User == MessageRole::Assistant {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_agent_config_default() -> TestResult {
    let config = AgentConfig::default();
    if config.name != [0u8; 32] {
        return TestResult::Fail;
    }
    if !config.system_prompt.is_empty() {
        return TestResult::Fail;
    }
    if config.max_tokens != 4096 {
        return TestResult::Fail;
    }
    if config.temperature != 70 {
        return TestResult::Fail;
    }
    if config.tools_enabled != [false; 16] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_agent_config_custom() -> TestResult {
    let mut config = AgentConfig::default();
    config.name[..4].copy_from_slice(b"Test");
    config.system_prompt = b"You are a test agent".to_vec();
    config.max_tokens = 8192;
    config.temperature = 50;
    config.tools_enabled[0] = true;
    config.tools_enabled[5] = true;

    if &config.name[..4] != b"Test" {
        return TestResult::Fail;
    }
    if config.system_prompt.as_slice() != b"You are a test agent" {
        return TestResult::Fail;
    }
    if config.max_tokens != 8192 {
        return TestResult::Fail;
    }
    if config.temperature != 50 {
        return TestResult::Fail;
    }
    if !config.tools_enabled[0] {
        return TestResult::Fail;
    }
    if !config.tools_enabled[5] {
        return TestResult::Fail;
    }
    if config.tools_enabled[1] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_agent_new() -> TestResult {
    let config = AgentConfig::default();
    let agent = Agent::new(1, config);

    if agent.id != 1 {
        return TestResult::Fail;
    }
    if agent.state != AgentState::Idle {
        return TestResult::Fail;
    }
    if !agent.messages.is_empty() {
        return TestResult::Fail;
    }
    if !agent.output.is_empty() {
        return TestResult::Fail;
    }
    if agent.created_at == 0 {
        return TestResult::Fail;
    }
    if agent.last_run != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_agent_with_custom_config() -> TestResult {
    let mut config = AgentConfig::default();
    config.name[..11].copy_from_slice(b"TestAgent01");
    config.max_tokens = 2048;

    let agent = Agent::new(42, config);

    if agent.id != 42 {
        return TestResult::Fail;
    }
    if &agent.config.name[..11] != b"TestAgent01" {
        return TestResult::Fail;
    }
    if agent.config.max_tokens != 2048 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_agent_name_extraction() -> TestResult {
    let mut config = AgentConfig::default();
    config.name[..7].copy_from_slice(b"TestBot");

    let agent = Agent::new(1, config);
    if agent.name() != b"TestBot" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_agent_add_message() -> TestResult {
    let config = AgentConfig::default();
    let mut agent = Agent::new(1, config);

    if !agent.messages.is_empty() {
        return TestResult::Fail;
    }

    agent.add_message(MessageRole::User, b"Hello");
    if agent.messages.len() != 1 {
        return TestResult::Fail;
    }
    if agent.messages[0].role != MessageRole::User {
        return TestResult::Fail;
    }
    if agent.messages[0].content.as_slice() != b"Hello" {
        return TestResult::Fail;
    }

    agent.add_message(MessageRole::Assistant, b"Hi there!");
    if agent.messages.len() != 2 {
        return TestResult::Fail;
    }
    if agent.messages[1].role != MessageRole::Assistant {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_agent_multiple_messages() -> TestResult {
    let config = AgentConfig::default();
    let mut agent = Agent::new(1, config);

    agent.add_message(MessageRole::System, b"System prompt");
    agent.add_message(MessageRole::User, b"User message 1");
    agent.add_message(MessageRole::Assistant, b"Response 1");
    agent.add_message(MessageRole::User, b"User message 2");
    agent.add_message(MessageRole::Tool, b"Tool result");
    agent.add_message(MessageRole::Assistant, b"Response 2");

    if agent.messages.len() != 6 {
        return TestResult::Fail;
    }
    if agent.messages[0].role != MessageRole::System {
        return TestResult::Fail;
    }
    if agent.messages[4].role != MessageRole::Tool {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_agent_clear_messages() -> TestResult {
    let config = AgentConfig::default();
    let mut agent = Agent::new(1, config);

    agent.add_message(MessageRole::User, b"Message 1");
    agent.add_message(MessageRole::User, b"Message 2");
    agent.add_message(MessageRole::User, b"Message 3");
    if agent.messages.len() != 3 {
        return TestResult::Fail;
    }

    agent.clear_messages();
    if !agent.messages.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_agent_state_changes() -> TestResult {
    let config = AgentConfig::default();
    let mut agent = Agent::new(1, config);

    if agent.state != AgentState::Idle {
        return TestResult::Fail;
    }

    agent.state = AgentState::Running;
    if agent.state != AgentState::Running {
        return TestResult::Fail;
    }

    agent.state = AgentState::Paused;
    if agent.state != AgentState::Paused {
        return TestResult::Fail;
    }

    agent.state = AgentState::Complete;
    if agent.state != AgentState::Complete {
        return TestResult::Fail;
    }

    agent.state = AgentState::Error;
    if agent.state != AgentState::Error {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_agent_output() -> TestResult {
    let config = AgentConfig::default();
    let mut agent = Agent::new(1, config);

    if !agent.output.is_empty() {
        return TestResult::Fail;
    }

    agent.output = b"Some output".to_vec();
    if agent.output.as_slice() != b"Some output" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_agent_clone() -> TestResult {
    let mut config = AgentConfig::default();
    config.name[..4].copy_from_slice(b"Test");

    let mut agent = Agent::new(1, config);
    agent.add_message(MessageRole::User, b"Hello");
    agent.output = b"Output".to_vec();

    let cloned = agent.clone();
    if cloned.id != agent.id {
        return TestResult::Fail;
    }
    if cloned.config.name != agent.config.name {
        return TestResult::Fail;
    }
    if cloned.messages.len() != agent.messages.len() {
        return TestResult::Fail;
    }
    if cloned.output != agent.output {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_agent_config_clone() -> TestResult {
    let mut config = AgentConfig::default();
    config.name[..4].copy_from_slice(b"Test");
    config.max_tokens = 8192;

    let cloned = config.clone();
    if cloned.name != config.name {
        return TestResult::Fail;
    }
    if cloned.max_tokens != config.max_tokens {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_agent_message_clone() -> TestResult {
    let msg = AgentMessage { role: MessageRole::User, content: b"Test content".to_vec() };

    let cloned = msg.clone();
    if cloned.role != MessageRole::User {
        return TestResult::Fail;
    }
    if cloned.content != b"Test content".to_vec() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_agent_tools_enabled() -> TestResult {
    let mut config = AgentConfig::default();
    config.tools_enabled[0] = true;
    config.tools_enabled[7] = true;
    config.tools_enabled[15] = true;

    if !config.tools_enabled[0] {
        return TestResult::Fail;
    }
    if config.tools_enabled[1] {
        return TestResult::Fail;
    }
    if !config.tools_enabled[7] {
        return TestResult::Fail;
    }
    if config.tools_enabled[8] {
        return TestResult::Fail;
    }
    if !config.tools_enabled[15] {
        return TestResult::Fail;
    }

    let enabled_count = config.tools_enabled.iter().filter(|&&x| x).count();
    if enabled_count != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_agent_unique_ids() -> TestResult {
    let config1 = AgentConfig::default();
    let config2 = AgentConfig::default();

    let agent1 = Agent::new(1, config1);
    let agent2 = Agent::new(2, config2);

    if agent1.id == agent2.id {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_agent_empty_name() -> TestResult {
    let config = AgentConfig::default();
    let agent = Agent::new(1, config);

    if !agent.name().is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
