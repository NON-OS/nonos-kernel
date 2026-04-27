// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for agents/registry.rs

use crate::agents::core::AgentConfig;
use crate::agents::registry::{
    agent_count, create_agent, delete_agent, get_agent, list_agents, update_agent, with_agent_mut,
    MAX_AGENTS,
};
use crate::test::framework::TestResult;

pub(crate) fn test_create_agent() -> TestResult {
    let config = AgentConfig::default();
    let id = create_agent(config);
    if id == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_create_agent_unique_ids() -> TestResult {
    let id1 = create_agent(AgentConfig::default());
    let id2 = create_agent(AgentConfig::default());
    let id3 = create_agent(AgentConfig::default());

    if id1 == id2 {
        return TestResult::Fail;
    }
    if id2 == id3 {
        return TestResult::Fail;
    }
    if id1 == id3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_agent() -> TestResult {
    let mut config = AgentConfig::default();
    config.name[..4].copy_from_slice(b"Test");

    let id = create_agent(config);
    let agent = get_agent(id);

    if agent.is_none() {
        return TestResult::Fail;
    }
    let agent = agent.unwrap();
    if agent.id != id {
        return TestResult::Fail;
    }
    if &agent.config.name[..4] != b"Test" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_agent_nonexistent() -> TestResult {
    let agent = get_agent(999999);
    if agent.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_with_agent_mut() -> TestResult {
    let config = AgentConfig::default();
    let id = create_agent(config);

    let result = with_agent_mut(id, |agent| {
        agent.output = b"modified".to_vec();
        42
    });

    if result != Some(42) {
        return TestResult::Fail;
    }

    let agent = get_agent(id).unwrap();
    if agent.output.as_slice() != b"modified" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_with_agent_mut_nonexistent() -> TestResult {
    let result = with_agent_mut(999999, |_| 42);
    if result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_update_agent() -> TestResult {
    let config = AgentConfig::default();
    let id = create_agent(config);

    let success = update_agent(id, |agent| {
        agent.output = b"updated".to_vec();
    });

    if !success {
        return TestResult::Fail;
    }

    let agent = get_agent(id).unwrap();
    if agent.output.as_slice() != b"updated" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_update_agent_nonexistent() -> TestResult {
    let success = update_agent(999999, |_| {});
    if success {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_list_agents() -> TestResult {
    let mut config1 = AgentConfig::default();
    config1.name[..6].copy_from_slice(b"Agent1");
    let mut config2 = AgentConfig::default();
    config2.name[..6].copy_from_slice(b"Agent2");

    create_agent(config1);
    create_agent(config2);

    let agents = list_agents();
    if agents.len() < 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delete_agent() -> TestResult {
    let config = AgentConfig::default();
    let id = create_agent(config);

    if get_agent(id).is_none() {
        return TestResult::Fail;
    }

    let result = delete_agent(id);
    if !result {
        return TestResult::Fail;
    }

    if get_agent(id).is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delete_agent_nonexistent() -> TestResult {
    let result = delete_agent(999999);
    if result {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_delete_agent_twice() -> TestResult {
    let config = AgentConfig::default();
    let id = create_agent(config);

    if !delete_agent(id) {
        return TestResult::Fail;
    }
    if delete_agent(id) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_agent_count() -> TestResult {
    let before = agent_count();
    create_agent(AgentConfig::default());
    let after = agent_count();
    if after < before {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_agents_constant() -> TestResult {
    if MAX_AGENTS != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_agent_config_preserved() -> TestResult {
    let mut config = AgentConfig::default();
    config.name[..8].copy_from_slice(b"MyAgent!");
    config.max_tokens = 2048;
    config.temperature = 80;
    config.tools_enabled[0] = true;
    config.tools_enabled[5] = true;
    config.system_prompt = b"Custom prompt".to_vec();

    let id = create_agent(config);
    let agent = get_agent(id).unwrap();

    if &agent.config.name[..8] != b"MyAgent!" {
        return TestResult::Fail;
    }
    if agent.config.max_tokens != 2048 {
        return TestResult::Fail;
    }
    if agent.config.temperature != 80 {
        return TestResult::Fail;
    }
    if !agent.config.tools_enabled[0] {
        return TestResult::Fail;
    }
    if !agent.config.tools_enabled[5] {
        return TestResult::Fail;
    }
    if agent.config.tools_enabled[1] {
        return TestResult::Fail;
    }
    if agent.config.system_prompt.as_slice() != b"Custom prompt" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_list_agents_returns_id_and_name() -> TestResult {
    let mut config = AgentConfig::default();
    config.name[..7].copy_from_slice(b"ListBot");

    let id = create_agent(config);
    let agents = list_agents();

    let found = agents.iter().find(|(aid, _)| *aid == id);
    if found.is_none() {
        return TestResult::Fail;
    }

    let (_, name) = found.unwrap();
    if &name[..7] != b"ListBot" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_agent_isolation() -> TestResult {
    let config1 = AgentConfig::default();
    let config2 = AgentConfig::default();

    let id1 = create_agent(config1);
    let id2 = create_agent(config2);

    update_agent(id1, |a| a.output = b"output1".to_vec());
    update_agent(id2, |a| a.output = b"output2".to_vec());

    if get_agent(id1).unwrap().output.as_slice() != b"output1" {
        return TestResult::Fail;
    }
    if get_agent(id2).unwrap().output.as_slice() != b"output2" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiple_operations() -> TestResult {
    let config = AgentConfig::default();
    let id = create_agent(config);

    update_agent(id, |a| a.output = b"step1".to_vec());
    with_agent_mut(id, |a| a.output.extend_from_slice(b"_step2"));

    let agent = get_agent(id).unwrap();
    if agent.output.as_slice() != b"step1_step2" {
        return TestResult::Fail;
    }
    TestResult::Pass
}
