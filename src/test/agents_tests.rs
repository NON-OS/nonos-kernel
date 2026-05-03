// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;

use super::framework::{TestCase, TestResult, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("Agents");

    suite.add(TestCase::new("agent_config_default", test_agent_config_default, "agents"));
    suite.add(TestCase::new("agent_creation", test_agent_creation, "agents"));
    suite.add(TestCase::new("agent_state_transitions", test_agent_state_transitions, "agents"));
    suite.add(TestCase::new("agent_messages", test_agent_messages, "agents"));
    suite.add(TestCase::new("agent_registry", test_agent_registry, "agents"));
    suite.add(TestCase::new("agent_tools", test_agent_tools, "agents"));
    suite.add(TestCase::new("agent_memory", test_agent_memory, "agents"));
    suite.add(TestCase::new("agent_context", test_agent_context, "agents"));
    suite.add(TestCase::new("agent_tasks", test_agent_tasks, "agents"));
    suite.add(TestCase::new("agent_scheduler", test_agent_scheduler, "agents"));
    suite.add(TestCase::new("agent_presets", test_agent_presets, "agents"));

    let (_, failed, _) = suite.run_all();
    failed == 0
}

pub(crate) fn test_agent_config_default() -> TestResult {
    use crate::agents::AgentConfig;

    let config = AgentConfig::default();

    if config.max_tokens != 4096 {
        return TestResult::Fail;
    }
    if config.temperature != 70 {
        return TestResult::Fail;
    }
    if config.name[0] != 0 {
        return TestResult::Fail;
    }

    for enabled in config.tools_enabled.iter() {
        if *enabled {
            return TestResult::Fail;
        }
    }

    TestResult::Pass
}

pub(crate) fn test_agent_creation() -> TestResult {
    use crate::agents::{Agent, AgentConfig};

    let mut config = AgentConfig::default();
    config.name[..4].copy_from_slice(b"Test");
    config.max_tokens = 8192;

    let agent = Agent::new(1, config);

    if agent.id != 1 {
        return TestResult::Fail;
    }
    if agent.config.max_tokens != 8192 {
        return TestResult::Fail;
    }
    if agent.name() != b"Test" {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_agent_state_transitions() -> TestResult {
    use crate::agents::core::{Agent, AgentConfig, AgentState};

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

pub(crate) fn test_agent_messages() -> TestResult {
    use crate::agents::core::{Agent, AgentConfig, MessageRole};

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

    agent.add_message(MessageRole::Assistant, b"Hi there");
    if agent.messages.len() != 2 {
        return TestResult::Fail;
    }

    agent.clear_messages();
    if !agent.messages.is_empty() {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_agent_registry() -> TestResult {
    use crate::agents::{create_agent, delete_agent, get_agent, list_agents, AgentConfig};

    let mut config = AgentConfig::default();
    config.name[..8].copy_from_slice(b"TestReg\0");

    let id = create_agent(config.clone());
    if id == 0 {
        return TestResult::Fail;
    }

    let agent = get_agent(id);
    if agent.is_none() {
        return TestResult::Fail;
    }

    let agents = list_agents();
    if !agents.iter().any(|a| a.id == id) {
        return TestResult::Fail;
    }

    if !delete_agent(id) {
        return TestResult::Fail;
    }

    let agent_after = get_agent(id);
    if agent_after.is_some() {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_agent_tools() -> TestResult {
    use crate::agents::tools::{execute_tool, list_tools, register_tool, ToolResult};

    let initial_count = list_tools().len();

    let registered =
        register_tool(b"test_tool", |_args| ToolResult::Success(b"tool executed".to_vec()));
    if !registered {
        return TestResult::Fail;
    }

    let tools = list_tools();
    if tools.len() != initial_count + 1 {
        return TestResult::Fail;
    }

    let result = execute_tool(b"test_tool", b"");
    match result {
        ToolResult::Success(output) => {
            if output.as_slice() != b"tool executed" {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }

    TestResult::Pass
}

pub(crate) fn test_agent_memory() -> TestResult {
    use crate::agents::memory::{AgentMemory, MAX_ENTRIES};

    if MAX_ENTRIES != 1024 {
        return TestResult::Fail;
    }

    let mem = AgentMemory::new(9999);
    if mem.agent_id != 9999 {
        return TestResult::Fail;
    }

    mem.store(b"key1", b"value1", 5);
    let recalled = mem.recall(b"key1");
    if recalled.is_none() {
        return TestResult::Fail;
    }
    if recalled.unwrap().as_slice() != b"value1" {
        return TestResult::Fail;
    }

    let not_found = mem.recall(b"nonexistent");
    if not_found.is_some() {
        return TestResult::Fail;
    }

    mem.store(b"key1", b"updated", 5);
    let updated = mem.recall(b"key1");
    if updated.is_none() {
        return TestResult::Fail;
    }
    if updated.unwrap().as_slice() != b"updated" {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_agent_context() -> TestResult {
    use crate::agents::context::AgentContext;

    let mut ctx = AgentContext::new(1);

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

    ctx.set_env(b"PATH", b"/bin");
    let path = ctx.get_env(b"PATH");
    if path.is_none() {
        return TestResult::Fail;
    }
    if path.unwrap() != b"/bin" {
        return TestResult::Fail;
    }

    ctx.add_history(b"ls -la");
    if ctx.history.len() != 1 {
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

pub(crate) fn test_agent_tasks() -> TestResult {
    use crate::agents::tasks::{create_task, get_task, update_task_status, TaskStatus, MAX_TASKS};

    if MAX_TASKS != 64 {
        return TestResult::Fail;
    }

    let id = create_task(1, b"Test task");
    if id == 0 {
        return TestResult::Fail;
    }

    let task = get_task(id);
    if task.is_none() {
        return TestResult::Fail;
    }

    let task = task.unwrap();
    if task.status != TaskStatus::Pending {
        return TestResult::Fail;
    }
    if task.description.as_slice() != b"Test task" {
        return TestResult::Fail;
    }

    update_task_status(id, TaskStatus::Running, None);
    let updated = get_task(id).unwrap();
    if updated.status != TaskStatus::Running {
        return TestResult::Fail;
    }

    update_task_status(id, TaskStatus::Complete, Some(b"Done"));
    let completed = get_task(id).unwrap();
    if completed.status != TaskStatus::Complete {
        return TestResult::Fail;
    }
    if completed.result.as_slice() != b"Done" {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_agent_scheduler() -> TestResult {
    use crate::agents::scheduler::{
        active_count, cancel_schedule, schedule_once, schedule_repeat, MAX_SCHEDULED,
    };

    if MAX_SCHEDULED != 32 {
        return TestResult::Fail;
    }

    let before = active_count();

    let id = schedule_once(1, b"scheduled task", 100000);
    if id == 0 {
        return TestResult::Fail;
    }

    let after = active_count();
    if after < before {
        return TestResult::Fail;
    }

    let repeat_id = schedule_repeat(1, b"repeat task", 5000);
    if repeat_id == 0 {
        return TestResult::Fail;
    }
    if repeat_id == id {
        return TestResult::Fail;
    }

    if !cancel_schedule(id) {
        return TestResult::Fail;
    }
    if cancel_schedule(id) {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_agent_presets() -> TestResult {
    use crate::agents::presets::{
        coding_assistant, file_manager_agent, list_presets, system_monitor, task_automator,
        web_researcher,
    };

    let presets = list_presets();
    if presets.len() != 5 {
        return TestResult::Fail;
    }

    let coding = coding_assistant();
    if coding.max_tokens != 4096 {
        return TestResult::Fail;
    }
    if coding.temperature != 70 {
        return TestResult::Fail;
    }
    if coding.system_prompt.is_empty() {
        return TestResult::Fail;
    }

    let file_mgr = file_manager_agent();
    if file_mgr.system_prompt.is_empty() {
        return TestResult::Fail;
    }

    let monitor = system_monitor();
    if monitor.system_prompt.is_empty() {
        return TestResult::Fail;
    }

    let web = web_researcher();
    if web.max_tokens != 8192 {
        return TestResult::Fail;
    }

    let automator = task_automator();
    if automator.system_prompt.is_empty() {
        return TestResult::Fail;
    }

    TestResult::Pass
}
