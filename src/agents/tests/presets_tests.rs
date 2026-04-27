// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for agents/presets.rs

use crate::agents::presets::{
    coding_assistant, file_manager_agent, list_presets, system_monitor, task_automator,
    web_researcher,
};
use crate::test::framework::TestResult;

pub(crate) fn test_coding_assistant_preset() -> TestResult {
    let config = coding_assistant();

    if &config.name[..15] != b"Code Assistant\0" {
        return TestResult::Fail;
    }
    if config.system_prompt.is_empty() {
        return TestResult::Fail;
    }
    if !config.tools_enabled[0] {
        return TestResult::Fail;
    }
    if !config.tools_enabled[1] {
        return TestResult::Fail;
    }
    if !config.tools_enabled[2] {
        return TestResult::Fail;
    }
    if config.tools_enabled[3] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_file_manager_preset() -> TestResult {
    let config = file_manager_agent();

    if &config.name[..12] != b"File Manager" {
        return TestResult::Fail;
    }
    if config.system_prompt.is_empty() {
        return TestResult::Fail;
    }
    if config.tools_enabled[0] {
        return TestResult::Fail;
    }
    if !config.tools_enabled[1] {
        return TestResult::Fail;
    }
    if !config.tools_enabled[2] {
        return TestResult::Fail;
    }
    if !config.tools_enabled[3] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_system_monitor_preset() -> TestResult {
    let config = system_monitor();

    if &config.name[..14] != b"System Monitor" {
        return TestResult::Fail;
    }
    if config.system_prompt.is_empty() {
        return TestResult::Fail;
    }
    if !config.tools_enabled[0] {
        return TestResult::Fail;
    }
    if config.tools_enabled[1] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_web_researcher_preset() -> TestResult {
    let config = web_researcher();

    if &config.name[..14] != b"Web Researcher" {
        return TestResult::Fail;
    }
    if config.system_prompt.is_empty() {
        return TestResult::Fail;
    }
    if config.max_tokens != 8192 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_task_automator_preset() -> TestResult {
    let config = task_automator();

    if &config.name[..14] != b"Task Automator" {
        return TestResult::Fail;
    }
    if config.system_prompt.is_empty() {
        return TestResult::Fail;
    }
    if !config.tools_enabled[0] {
        return TestResult::Fail;
    }
    if !config.tools_enabled[1] {
        return TestResult::Fail;
    }
    if !config.tools_enabled[2] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_list_presets() -> TestResult {
    let presets = list_presets();

    if presets.len() != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_list_presets_names() -> TestResult {
    let presets = list_presets();

    if presets[0].0 != b"Code Assistant" {
        return TestResult::Fail;
    }
    if presets[1].0 != b"File Manager" {
        return TestResult::Fail;
    }
    if presets[2].0 != b"System Monitor" {
        return TestResult::Fail;
    }
    if presets[3].0 != b"Web Researcher" {
        return TestResult::Fail;
    }
    if presets[4].0 != b"Task Automator" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_list_presets_callable() -> TestResult {
    let presets = list_presets();

    for (_, factory) in presets {
        let config = factory();
        if config.name[0] == 0 && config.system_prompt.is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_preset_default_max_tokens() -> TestResult {
    let coding = coding_assistant();
    let file_mgr = file_manager_agent();
    let monitor = system_monitor();
    let automator = task_automator();

    if coding.max_tokens != 4096 {
        return TestResult::Fail;
    }
    if file_mgr.max_tokens != 4096 {
        return TestResult::Fail;
    }
    if monitor.max_tokens != 4096 {
        return TestResult::Fail;
    }
    if automator.max_tokens != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_preset_default_temperature() -> TestResult {
    let config = coding_assistant();
    if config.temperature != 70 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_presets_are_independent() -> TestResult {
    let config1 = coding_assistant();
    let config2 = coding_assistant();

    if config1.name != config2.name {
        return TestResult::Fail;
    }
    if config1.max_tokens != config2.max_tokens {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_preset_system_prompts_not_empty() -> TestResult {
    if coding_assistant().system_prompt.is_empty() {
        return TestResult::Fail;
    }
    if file_manager_agent().system_prompt.is_empty() {
        return TestResult::Fail;
    }
    if system_monitor().system_prompt.is_empty() {
        return TestResult::Fail;
    }
    if web_researcher().system_prompt.is_empty() {
        return TestResult::Fail;
    }
    if task_automator().system_prompt.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_preset_tool_configurations() -> TestResult {
    let coding = coding_assistant();
    let enabled_count = coding.tools_enabled.iter().filter(|&&x| x).count();
    if enabled_count != 3 {
        return TestResult::Fail;
    }

    let file_mgr = file_manager_agent();
    let enabled_count = file_mgr.tools_enabled.iter().filter(|&&x| x).count();
    if enabled_count != 3 {
        return TestResult::Fail;
    }

    let monitor = system_monitor();
    let enabled_count = monitor.tools_enabled.iter().filter(|&&x| x).count();
    if enabled_count != 1 {
        return TestResult::Fail;
    }

    let web = web_researcher();
    let enabled_count = web.tools_enabled.iter().filter(|&&x| x).count();
    if enabled_count != 0 {
        return TestResult::Fail;
    }

    let automator = task_automator();
    let enabled_count = automator.tools_enabled.iter().filter(|&&x| x).count();
    if enabled_count != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
