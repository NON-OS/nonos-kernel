// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for agents/presets.rs

use crate::agents::presets::{
    coding_assistant, file_manager_agent, system_monitor,
    web_researcher, task_automator, list_presets
};

#[test]
fn test_coding_assistant_preset() {
    let config = coding_assistant();

    assert_eq!(&config.name[..15], b"Code Assistant\0");
    assert!(!config.system_prompt.is_empty());
    assert!(config.tools_enabled[0]);
    assert!(config.tools_enabled[1]);
    assert!(config.tools_enabled[2]);
    assert!(!config.tools_enabled[3]);
}

#[test]
fn test_file_manager_preset() {
    let config = file_manager_agent();

    assert_eq!(&config.name[..12], b"File Manager");
    assert!(!config.system_prompt.is_empty());
    assert!(!config.tools_enabled[0]);
    assert!(config.tools_enabled[1]);
    assert!(config.tools_enabled[2]);
    assert!(config.tools_enabled[3]);
}

#[test]
fn test_system_monitor_preset() {
    let config = system_monitor();

    assert_eq!(&config.name[..14], b"System Monitor");
    assert!(!config.system_prompt.is_empty());
    assert!(config.tools_enabled[0]);
    assert!(!config.tools_enabled[1]);
}

#[test]
fn test_web_researcher_preset() {
    let config = web_researcher();

    assert_eq!(&config.name[..14], b"Web Researcher");
    assert!(!config.system_prompt.is_empty());
    assert_eq!(config.max_tokens, 8192);
}

#[test]
fn test_task_automator_preset() {
    let config = task_automator();

    assert_eq!(&config.name[..14], b"Task Automator");
    assert!(!config.system_prompt.is_empty());
    assert!(config.tools_enabled[0]);
    assert!(config.tools_enabled[1]);
    assert!(config.tools_enabled[2]);
}

#[test]
fn test_list_presets() {
    let presets = list_presets();

    assert_eq!(presets.len(), 5);
}

#[test]
fn test_list_presets_names() {
    let presets = list_presets();

    assert_eq!(presets[0].0, b"Code Assistant");
    assert_eq!(presets[1].0, b"File Manager");
    assert_eq!(presets[2].0, b"System Monitor");
    assert_eq!(presets[3].0, b"Web Researcher");
    assert_eq!(presets[4].0, b"Task Automator");
}

#[test]
fn test_list_presets_callable() {
    let presets = list_presets();

    for (_, factory) in presets {
        let config = factory();
        assert!(config.name[0] != 0 || config.system_prompt.is_empty() == false);
    }
}

#[test]
fn test_preset_default_max_tokens() {
    let coding = coding_assistant();
    let file_mgr = file_manager_agent();
    let monitor = system_monitor();
    let automator = task_automator();

    assert_eq!(coding.max_tokens, 4096);
    assert_eq!(file_mgr.max_tokens, 4096);
    assert_eq!(monitor.max_tokens, 4096);
    assert_eq!(automator.max_tokens, 4096);
}

#[test]
fn test_preset_default_temperature() {
    let config = coding_assistant();
    assert_eq!(config.temperature, 70);
}

#[test]
fn test_presets_are_independent() {
    let config1 = coding_assistant();
    let config2 = coding_assistant();

    assert_eq!(config1.name, config2.name);
    assert_eq!(config1.max_tokens, config2.max_tokens);
}

#[test]
fn test_preset_system_prompts_not_empty() {
    assert!(!coding_assistant().system_prompt.is_empty());
    assert!(!file_manager_agent().system_prompt.is_empty());
    assert!(!system_monitor().system_prompt.is_empty());
    assert!(!web_researcher().system_prompt.is_empty());
    assert!(!task_automator().system_prompt.is_empty());
}

#[test]
fn test_preset_tool_configurations() {
    let coding = coding_assistant();
    let enabled_count = coding.tools_enabled.iter().filter(|&&x| x).count();
    assert_eq!(enabled_count, 3);

    let file_mgr = file_manager_agent();
    let enabled_count = file_mgr.tools_enabled.iter().filter(|&&x| x).count();
    assert_eq!(enabled_count, 3);

    let monitor = system_monitor();
    let enabled_count = monitor.tools_enabled.iter().filter(|&&x| x).count();
    assert_eq!(enabled_count, 1);

    let web = web_researcher();
    let enabled_count = web.tools_enabled.iter().filter(|&&x| x).count();
    assert_eq!(enabled_count, 0);

    let automator = task_automator();
    let enabled_count = automator.tools_enabled.iter().filter(|&&x| x).count();
    assert_eq!(enabled_count, 3);
}
