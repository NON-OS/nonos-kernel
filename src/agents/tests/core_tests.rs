// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for agents/core.rs - Agent, AgentConfig, AgentState, MessageRole

use crate::agents::core::{Agent, AgentConfig, AgentState, AgentMessage, MessageRole};

#[test_case]
fn test_agent_state_variants() {
    assert_eq!(AgentState::Idle, AgentState::Idle);
    assert_eq!(AgentState::Running, AgentState::Running);
    assert_eq!(AgentState::Paused, AgentState::Paused);
    assert_eq!(AgentState::Error, AgentState::Error);
    assert_eq!(AgentState::Complete, AgentState::Complete);
    assert_ne!(AgentState::Idle, AgentState::Running);
}

#[test_case]
fn test_message_role_variants() {
    assert_eq!(MessageRole::System, MessageRole::System);
    assert_eq!(MessageRole::User, MessageRole::User);
    assert_eq!(MessageRole::Assistant, MessageRole::Assistant);
    assert_eq!(MessageRole::Tool, MessageRole::Tool);
    assert_ne!(MessageRole::User, MessageRole::Assistant);
}

#[test_case]
fn test_agent_config_default() {
    let config = AgentConfig::default();
    assert_eq!(config.name, [0u8; 32]);
    assert!(config.system_prompt.is_empty());
    assert_eq!(config.max_tokens, 4096);
    assert_eq!(config.temperature, 70);
    assert_eq!(config.tools_enabled, [false; 16]);
}

#[test_case]
fn test_agent_config_custom() {
    let mut config = AgentConfig::default();
    config.name[..4].copy_from_slice(b"Test");
    config.system_prompt = b"You are a test agent".to_vec();
    config.max_tokens = 8192;
    config.temperature = 50;
    config.tools_enabled[0] = true;
    config.tools_enabled[5] = true;

    assert_eq!(&config.name[..4], b"Test");
    assert_eq!(config.system_prompt.as_slice(), b"You are a test agent");
    assert_eq!(config.max_tokens, 8192);
    assert_eq!(config.temperature, 50);
    assert!(config.tools_enabled[0]);
    assert!(config.tools_enabled[5]);
    assert!(!config.tools_enabled[1]);
}

#[test_case]
fn test_agent_new() {
    let config = AgentConfig::default();
    let agent = Agent::new(1, config);

    assert_eq!(agent.id, 1);
    assert_eq!(agent.state, AgentState::Idle);
    assert!(agent.messages.is_empty());
    assert!(agent.output.is_empty());
    assert!(agent.created_at > 0);
    assert_eq!(agent.last_run, 0);
}

#[test_case]
fn test_agent_with_custom_config() {
    let mut config = AgentConfig::default();
    config.name[..11].copy_from_slice(b"TestAgent01");
    config.max_tokens = 2048;

    let agent = Agent::new(42, config);

    assert_eq!(agent.id, 42);
    assert_eq!(&agent.config.name[..11], b"TestAgent01");
    assert_eq!(agent.config.max_tokens, 2048);
}

#[test_case]
fn test_agent_add_message() {
    let config = AgentConfig::default();
    let mut agent = Agent::new(1, config);

    assert!(agent.messages.is_empty());

    agent.add_message(MessageRole::User, b"Hello");
    assert_eq!(agent.messages.len(), 1);
    assert_eq!(agent.messages[0].role, MessageRole::User);
    assert_eq!(agent.messages[0].content.as_slice(), b"Hello");

    agent.add_message(MessageRole::Assistant, b"Hi there!");
    assert_eq!(agent.messages.len(), 2);
    assert_eq!(agent.messages[1].role, MessageRole::Assistant);
    assert_eq!(agent.messages[1].content.as_slice(), b"Hi there!");
}

#[test_case]
fn test_agent_add_multiple_messages() {
    let config = AgentConfig::default();
    let mut agent = Agent::new(1, config);

    agent.add_message(MessageRole::System, b"System prompt");
    agent.add_message(MessageRole::User, b"User message 1");
    agent.add_message(MessageRole::Assistant, b"Response 1");
    agent.add_message(MessageRole::User, b"User message 2");
    agent.add_message(MessageRole::Tool, b"Tool result");
    agent.add_message(MessageRole::Assistant, b"Response 2");

    assert_eq!(agent.messages.len(), 6);
    assert_eq!(agent.messages[0].role, MessageRole::System);
    assert_eq!(agent.messages[4].role, MessageRole::Tool);
}

#[test_case]
fn test_agent_clear_messages() {
    let config = AgentConfig::default();
    let mut agent = Agent::new(1, config);

    agent.add_message(MessageRole::User, b"Message 1");
    agent.add_message(MessageRole::User, b"Message 2");
    agent.add_message(MessageRole::User, b"Message 3");
    assert_eq!(agent.messages.len(), 3);

    agent.clear_messages();
    assert!(agent.messages.is_empty());
}

#[test_case]
fn test_agent_name_extraction() {
    let mut config = AgentConfig::default();
    config.name[..7].copy_from_slice(b"TestBot");

    let agent = Agent::new(1, config);
    assert_eq!(agent.name(), b"TestBot");
}

#[test_case]
fn test_agent_name_with_null_terminator() {
    let mut config = AgentConfig::default();
    config.name[..5].copy_from_slice(b"Agent");
    // Rest is already zeros (null bytes)

    let agent = Agent::new(1, config);
    assert_eq!(agent.name(), b"Agent");
}

#[test_case]
fn test_agent_name_full_length() {
    let mut config = AgentConfig::default();
    config.name = *b"12345678901234567890123456789012"; // 32 bytes, no null

    let agent = Agent::new(1, config);
    assert_eq!(agent.name().len(), 32);
}

#[test_case]
fn test_agent_message_clone() {
    let msg = AgentMessage {
        role: MessageRole::User,
        content: b"Test content".to_vec(),
    };

    let cloned = msg.clone();
    assert_eq!(cloned.role, MessageRole::User);
    assert_eq!(cloned.content, b"Test content".to_vec());
}

#[test_case]
fn test_agent_clone() {
    let mut config = AgentConfig::default();
    config.name[..4].copy_from_slice(b"Test");

    let mut agent = Agent::new(1, config);
    agent.add_message(MessageRole::User, b"Hello");
    agent.output = b"Output".to_vec();

    let cloned = agent.clone();
    assert_eq!(cloned.id, agent.id);
    assert_eq!(cloned.config.name, agent.config.name);
    assert_eq!(cloned.messages.len(), agent.messages.len());
    assert_eq!(cloned.output, agent.output);
}

#[test_case]
fn test_agent_state_transitions() {
    let config = AgentConfig::default();
    let mut agent = Agent::new(1, config);

    assert_eq!(agent.state, AgentState::Idle);

    agent.state = AgentState::Running;
    assert_eq!(agent.state, AgentState::Running);

    agent.state = AgentState::Paused;
    assert_eq!(agent.state, AgentState::Paused);

    agent.state = AgentState::Complete;
    assert_eq!(agent.state, AgentState::Complete);

    agent.state = AgentState::Error;
    assert_eq!(agent.state, AgentState::Error);
}

#[test_case]
fn test_agent_config_tools_enabled() {
    let mut config = AgentConfig::default();

    // Enable specific tools
    config.tools_enabled[0] = true;
    config.tools_enabled[7] = true;
    config.tools_enabled[15] = true;

    assert!(config.tools_enabled[0]);
    assert!(!config.tools_enabled[1]);
    assert!(config.tools_enabled[7]);
    assert!(!config.tools_enabled[8]);
    assert!(config.tools_enabled[15]);

    // Count enabled tools
    let enabled_count = config.tools_enabled.iter().filter(|&&x| x).count();
    assert_eq!(enabled_count, 3);
}

#[test_case]
fn test_agent_empty_message_content() {
    let config = AgentConfig::default();
    let mut agent = Agent::new(1, config);

    agent.add_message(MessageRole::User, b"");
    assert_eq!(agent.messages.len(), 1);
    assert!(agent.messages[0].content.is_empty());
}

#[test_case]
fn test_agent_large_message_content() {
    let config = AgentConfig::default();
    let mut agent = Agent::new(1, config);

    let large_content = [b'x'; 10000];
    agent.add_message(MessageRole::User, &large_content);

    assert_eq!(agent.messages.len(), 1);
    assert_eq!(agent.messages[0].content.len(), 10000);
}
