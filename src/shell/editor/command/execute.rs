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

use alloc::string::String;

use crate::shell::editor::state::Editor;

use super::types::{Command, CommandResult, SetCommand, SubstituteFlags};

pub fn execute_command(editor: &mut Editor, cmd: Command) -> CommandResult {
    match cmd {
        Command::Write(filename) => execute_write(editor, filename),
        Command::Quit => execute_quit(editor, false),
        Command::WriteQuit => {
            let write_result = execute_write(editor, None);
            if matches!(write_result, CommandResult::Error(_)) {
                return write_result;
            }
            execute_quit(editor, false)
        }
        Command::ForceQuit => execute_quit(editor, true),
        Command::Edit(filename) => execute_edit(editor, &filename),
        Command::Number(line) => execute_goto(editor, line),
        Command::Set(set_cmd) => execute_set(editor, set_cmd),
        Command::Substitute(pattern, replacement, flags) => {
            execute_substitute(editor, &pattern, &replacement, flags)
        }
        Command::Help => CommandResult::Message(String::from(
            ":w - write | :q - quit | :wq - write and quit | :e file - edit file",
        )),
        Command::Version => CommandResult::Message(String::from("NONOS Vi 1.0")),
        Command::Unknown(s) => CommandResult::Error(alloc::format!("Unknown command: {}", s)),
        _ => CommandResult::Continue,
    }
}

fn execute_write(editor: &mut Editor, filename: Option<String>) -> CommandResult {
    let filename = filename
        .or_else(|| editor.buffer().filename().map(String::from))
        .unwrap_or_default();

    if filename.is_empty() {
        return CommandResult::Error(String::from("No file name"));
    }

    let content = editor.buffer().to_string();

    match crate::fs::write_file(&filename, content.as_bytes()) {
        Ok(_) => {
            editor.buffer_mut().set_filename(&filename);
            editor.buffer_mut().mark_saved();
            let lines = editor.buffer().line_count();
            let bytes = content.len();
            CommandResult::Message(alloc::format!(
                "\"{}\" {}L, {}B written",
                filename, lines, bytes
            ))
        }
        Err(e) => CommandResult::Error(alloc::format!("Cannot write: {:?}", e)),
    }
}

fn execute_quit(editor: &mut Editor, force: bool) -> CommandResult {
    if !force && editor.buffer().is_modified() {
        return CommandResult::Error(String::from(
            "No write since last change (add ! to override)",
        ));
    }
    CommandResult::Quit
}

fn execute_edit(editor: &mut Editor, filename: &str) -> CommandResult {
    if filename.is_empty() {
        return CommandResult::Error(String::from("No file name"));
    }

    match crate::fs::read_file(filename) {
        Ok(content) => {
            let content_str = core::str::from_utf8(&content).unwrap_or("");
            editor.load_file(filename, content_str);
            let lines = editor.buffer().line_count();
            CommandResult::Message(alloc::format!("\"{}\" {}L", filename, lines))
        }
        Err(_) => {
            editor.new_file(filename);
            CommandResult::Message(alloc::format!("\"{}\" [New File]", filename))
        }
    }
}

fn execute_goto(editor: &mut Editor, line: usize) -> CommandResult {
    let target = line
        .saturating_sub(1)
        .min(editor.buffer().line_count().saturating_sub(1));
    editor.set_cursor(target, 0);
    CommandResult::Continue
}

fn execute_set(editor: &mut Editor, set_cmd: SetCommand) -> CommandResult {
    match set_cmd {
        SetCommand::Number(enabled) => {
            editor.config_mut().show_line_numbers = enabled;
        }
        SetCommand::RelativeNumber(enabled) => {
            editor.config_mut().relative_numbers = enabled;
        }
        SetCommand::TabStop(size) => {
            editor.config_mut().tab_width = size;
        }
        SetCommand::ExpandTab(enabled) => {
            editor.config_mut().expand_tab = enabled;
        }
        SetCommand::AutoIndent(enabled) => {
            editor.config_mut().auto_indent = enabled;
        }
        SetCommand::ShowMatch(enabled) => {
            editor.config_mut().show_matching = enabled;
        }
        SetCommand::IgnoreCase(enabled) => {
            editor.config_mut().ignore_case = enabled;
        }
        SetCommand::SmartCase(enabled) => {
            editor.config_mut().smart_case = enabled;
        }
        SetCommand::Wrap(enabled) => {
            editor.config_mut().wrap_lines = enabled;
        }
        SetCommand::List | SetCommand::All => {
            let config = editor.config();
            return CommandResult::Message(alloc::format!(
                "number={} tabstop={} expandtab={} autoindent={}",
                config.show_line_numbers,
                config.tab_width,
                config.expand_tab,
                config.auto_indent
            ));
        }
    }
    CommandResult::Continue
}

fn execute_substitute(
    editor: &mut Editor,
    pattern: &str,
    replacement: &str,
    flags: SubstituteFlags,
) -> CommandResult {
    if pattern.is_empty() {
        return CommandResult::Error(String::from("No previous substitute pattern"));
    }

    let row = editor.cursor_row();
    let mut count = 0;

    if let Some(line) = editor.buffer_mut().line_mut(row) {
        if flags.global {
            while line.content.contains(pattern) {
                line.content = line.content.replacen(pattern, replacement, 1);
                count += 1;
            }
        } else if line.content.contains(pattern) {
            line.content = line.content.replacen(pattern, replacement, 1);
            count = 1;
        }
    }

    if count > 0 {
        CommandResult::Message(alloc::format!("{} substitution(s)", count))
    } else {
        CommandResult::Error(String::from("Pattern not found"))
    }
}
