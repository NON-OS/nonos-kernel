// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for agents/registry.rs

use crate::agents::core::AgentConfig;
use crate::agents::registry::{
    create_agent, get_agent, with_agent_mut, update_agent,
    list_agents, delete_agent, agent_count, MAX_AGENTS
};

#[test_case]
fn test_create_agent() {
    let config = AgentConfig::default();
    let id = create_agent(config);
    assert!(id > 0);
}

#[test_case]
fn test_create_agent_unique_ids() {
    let id1 = create_agent(AgentConfig::default());
    let id2 = create_agent(AgentConfig::default());
    let id3 = create_agent(AgentConfig::default());

    assert_ne!(id1, id2);
    assert_ne!(id2, id3);
    assert_ne!(id1, id3);
}

#[test_case]
fn test_get_agent() {
    let mut config = AgentConfig::default();
    config.name[..4].copy_from_slice(b"Test");

    let id = create_agent(config);
    let agent = get_agent(id);

    assert!(agent.is_some());
    let agent = agent.unwrap();
    assert_eq!(agent.id, id);
    assert_eq!(&agent.config.name[..4], b"Test");
}

#[test_case]
fn test_get_agent_nonexistent() {
    let agent = get_agent(999999);
    assert!(agent.is_none());
}

#[test_case]
fn test_with_agent_mut() {
    let config = AgentConfig::default();
    let id = create_agent(config);

    let result = with_agent_mut(id, |agent| {
        agent.output = b"modified".to_vec();
        42
    });

    assert_eq!(result, Some(42));

    let agent = get_agent(id).unwrap();
    assert_eq!(agent.output.as_slice(), b"modified");
}

#[test_case]
fn test_with_agent_mut_nonexistent() {
    let result = with_agent_mut(999999, |_| 42);
    assert!(result.is_none());
}

#[test_case]
fn test_update_agent() {
    let config = AgentConfig::default();
    let id = create_agent(config);

    let success = update_agent(id, |agent| {
        agent.output = b"updated".to_vec();
    });

    assert!(success);

    let agent = get_agent(id).unwrap();
    assert_eq!(agent.output.as_slice(), b"updated");
}

#[test_case]
fn test_update_agent_nonexistent() {
    let success = update_agent(999999, |_| {});
    assert!(!success);
}

#[test_case]
fn test_list_agents() {
    let mut config1 = AgentConfig::default();
    config1.name[..6].copy_from_slice(b"Agent1");
    let mut config2 = AgentConfig::default();
    config2.name[..6].copy_from_slice(b"Agent2");

    create_agent(config1);
    create_agent(config2);

    let agents = list_agents();
    assert!(agents.len() >= 2);
}

#[test_case]
fn test_delete_agent() {
    let config = AgentConfig::default();
    let id = create_agent(config);

    assert!(get_agent(id).is_some());

    let result = delete_agent(id);
    assert!(result);

    assert!(get_agent(id).is_none());
}

#[test_case]
fn test_delete_agent_nonexistent() {
    let result = delete_agent(999999);
    assert!(!result);
}

#[test_case]
fn test_delete_agent_twice() {
    let config = AgentConfig::default();
    let id = create_agent(config);

    assert!(delete_agent(id));
    assert!(!delete_agent(id));
}

#[test_case]
fn test_agent_count() {
    let before = agent_count();
    create_agent(AgentConfig::default());
    let after = agent_count();
    assert!(after >= before);
}

#[test_case]
fn test_max_agents_constant() {
    assert_eq!(MAX_AGENTS, 32);
}

#[test_case]
fn test_agent_config_preserved() {
    let mut config = AgentConfig::default();
    config.name[..8].copy_from_slice(b"MyAgent!");
    config.max_tokens = 2048;
    config.temperature = 80;
    config.tools_enabled[0] = true;
    config.tools_enabled[5] = true;
    config.system_prompt = b"Custom prompt".to_vec();

    let id = create_agent(config);
    let agent = get_agent(id).unwrap();

    assert_eq!(&agent.config.name[..8], b"MyAgent!");
    assert_eq!(agent.config.max_tokens, 2048);
    assert_eq!(agent.config.temperature, 80);
    assert!(agent.config.tools_enabled[0]);
    assert!(agent.config.tools_enabled[5]);
    assert!(!agent.config.tools_enabled[1]);
    assert_eq!(agent.config.system_prompt.as_slice(), b"Custom prompt");
}

#[test_case]
fn test_list_agents_returns_id_and_name() {
    let mut config = AgentConfig::default();
    config.name[..7].copy_from_slice(b"ListBot");

    let id = create_agent(config);
    let agents = list_agents();

    let found = agents.iter().find(|(aid, _)| *aid == id);
    assert!(found.is_some());

    let (_, name) = found.unwrap();
    assert_eq!(&name[..7], b"ListBot");
}

#[test_case]
fn test_agent_isolation() {
    let config1 = AgentConfig::default();
    let config2 = AgentConfig::default();

    let id1 = create_agent(config1);
    let id2 = create_agent(config2);

    update_agent(id1, |a| a.output = b"output1".to_vec());
    update_agent(id2, |a| a.output = b"output2".to_vec());

    assert_eq!(get_agent(id1).unwrap().output.as_slice(), b"output1");
    assert_eq!(get_agent(id2).unwrap().output.as_slice(), b"output2");
}

#[test_case]
fn test_multiple_operations() {
    let config = AgentConfig::default();
    let id = create_agent(config);

    update_agent(id, |a| a.output = b"step1".to_vec());
    with_agent_mut(id, |a| a.output.extend_from_slice(b"_step2"));

    let agent = get_agent(id).unwrap();
    assert_eq!(agent.output.as_slice(), b"step1_step2");
}
