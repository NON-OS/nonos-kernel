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

use super::core::AgentConfig;

pub fn coding_assistant() -> AgentConfig {
    let mut cfg = AgentConfig::default();
    cfg.name[..14].copy_from_slice(b"Code Assistant");
    cfg.system_prompt =
        b"You are a coding assistant. Help with programming tasks, debugging, and code review."
            .to_vec();
    cfg.tools_enabled[0] = true;
    cfg.tools_enabled[1] = true;
    cfg.tools_enabled[2] = true;
    cfg
}

pub fn file_manager_agent() -> AgentConfig {
    let mut cfg = AgentConfig::default();
    cfg.name[..12].copy_from_slice(b"File Manager");
    cfg.system_prompt =
        b"You manage files and directories. Help organize, search, and manipulate files.".to_vec();
    cfg.tools_enabled[1] = true;
    cfg.tools_enabled[2] = true;
    cfg.tools_enabled[3] = true;
    cfg
}

pub fn system_monitor() -> AgentConfig {
    let mut cfg = AgentConfig::default();
    cfg.name[..14].copy_from_slice(b"System Monitor");
    cfg.system_prompt =
        b"You monitor system health, processes, and resources. Alert on issues.".to_vec();
    cfg.tools_enabled[0] = true;
    cfg
}

pub fn web_researcher() -> AgentConfig {
    let mut cfg = AgentConfig::default();
    cfg.name[..14].copy_from_slice(b"Web Researcher");
    cfg.system_prompt = b"You research topics online and summarize findings clearly.".to_vec();
    cfg.max_tokens = 8192;
    cfg
}

pub fn task_automator() -> AgentConfig {
    let mut cfg = AgentConfig::default();
    cfg.name[..14].copy_from_slice(b"Task Automator");
    cfg.system_prompt =
        b"You automate repetitive tasks. Create and run scripts efficiently.".to_vec();
    cfg.tools_enabled[0] = true;
    cfg.tools_enabled[1] = true;
    cfg.tools_enabled[2] = true;
    cfg
}

pub fn list_presets() -> &'static [(&'static [u8], fn() -> AgentConfig)] {
    &[
        (b"Code Assistant", coding_assistant as fn() -> AgentConfig),
        (b"File Manager", file_manager_agent as fn() -> AgentConfig),
        (b"System Monitor", system_monitor as fn() -> AgentConfig),
        (b"Web Researcher", web_researcher as fn() -> AgentConfig),
        (b"Task Automator", task_automator as fn() -> AgentConfig),
    ]
}
