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

use crate::shell::terminal::{show_prompt, clear_command};
use super::{builtins, pipeline, dispatch, expand, utils};

pub fn init() {
    builtins::init_env();
    builtins::init_aliases();
}

pub fn process(cmd: &[u8]) {
    let cmd = utils::trim_bytes(cmd);

    if cmd.is_empty() {
        clear_command();
        show_prompt();
        return;
    }

    let (cmd, is_background) = if cmd.ends_with(b"&") && cmd.len() > 1 {
        (utils::trim_bytes(&cmd[..cmd.len()-1]), true)
    } else {
        (cmd, false)
    };

    let var_expanded = expand::expand_variables(cmd);
    let cmd_after_var_expand = &var_expanded[..];

    let expanded_cmd: alloc::vec::Vec<u8>;
    let final_cmd = if let Some((expanded, len)) = builtins::expand_alias(cmd_after_var_expand) {
        expanded_cmd = expanded[..len].to_vec();
        &expanded_cmd[..]
    } else {
        cmd_after_var_expand
    };

    if is_background {
        let job_id = builtins::add_background_job(final_cmd);
        if job_id > 0 {
            let pipe = pipeline::Pipeline::parse(final_cmd);
            if pipe.is_simple() {
                dispatch::dispatch(pipe.stages[0].command);
            } else {
                execute_pipeline(&pipe);
            }
            builtins::complete_job(job_id);
        }
    } else {
        let pipe = pipeline::Pipeline::parse(final_cmd);
        if pipe.is_simple() {
            dispatch::dispatch(pipe.stages[0].command);
        } else {
            execute_pipeline(&pipe);
        }
    }

    clear_command();
    show_prompt();
}

fn execute_pipeline(pipe: &pipeline::Pipeline) {
    use crate::fs;

    let mut stdin_data: Option<alloc::vec::Vec<u8>> = None;

    for (i, stage) in pipe.stages.iter().enumerate() {
        let is_last = i == pipe.stages.len() - 1;

        if let Some(data) = stdin_data.take() {
            pipeline::set_stdin(data);
        }

        if stage.redirect_type == pipeline::RedirectType::Input {
            if let Some(path) = stage.redirect_target {
                if let Ok(path_str) = core::str::from_utf8(path) {
                    if let Ok(content) = fs::read_file(path_str) {
                        pipeline::set_stdin(content);
                    }
                }
            }
        }

        let should_capture = !is_last || matches!(
            stage.redirect_type,
            pipeline::RedirectType::Write | pipeline::RedirectType::Append
        );

        if should_capture {
            pipeline::start_capture();
        }

        dispatch::dispatch(stage.command);

        if should_capture {
            let output = pipeline::stop_capture();

            if is_last {
                handle_redirect(stage, &output);
            } else {
                stdin_data = Some(output);
            }
        }
    }
}

fn handle_redirect(stage: &pipeline::PipelineStage, output: &[u8]) {
    use crate::fs;
    use crate::shell::output::print_line;
    use crate::graphics::framebuffer::COLOR_RED;

    let target = match stage.redirect_target {
        Some(t) => t,
        None => {
            print_line(b"Redirect: no target file specified", COLOR_RED);
            return;
        }
    };

    let path_str = match core::str::from_utf8(target) {
        Ok(s) => s,
        Err(_) => {
            print_line(b"Redirect: invalid path", COLOR_RED);
            return;
        }
    };

    match stage.redirect_type {
        pipeline::RedirectType::Write => {
            if let Err(_) = fs::write_file(path_str, output) {
                print_line(b"Redirect: failed to write file", COLOR_RED);
            }
        }
        pipeline::RedirectType::Append => {
            let existing = fs::read_file(path_str).unwrap_or_default();
            let mut combined = existing;
            combined.extend_from_slice(output);
            if let Err(_) = fs::write_file(path_str, &combined) {
                print_line(b"Redirect: failed to append to file", COLOR_RED);
            }
        }
        _ => {}
    }
}

pub fn execute_for_gui(cmd: &[u8]) {
    let cmd = utils::trim_bytes(cmd);

    if cmd.is_empty() {
        return;
    }

    let var_expanded = expand::expand_variables(cmd);

    if let Some((expanded, len)) = builtins::expand_alias(&var_expanded) {
        dispatch::dispatch(&expanded[..len]);
    } else {
        dispatch::dispatch(&var_expanded);
    }
}
