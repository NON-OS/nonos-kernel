//! Command-line interface for kernel shell and early user interaction.

#![cfg(feature = "ui")]

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;
use spin::Mutex;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Command callback type.
pub type CmdCallback = Box<dyn Fn(&[&str]) -> Result<String, &'static str> + Send + Sync + 'static>;

struct Command {
    name: String,
    help: String,
    callback: CmdCallback,
}

static CLI_REGISTRY: Mutex<Option<Cli>> = Mutex::new(None);

/// CLI registry.
pub struct Cli {
    commands: BTreeMap<String, Command>,
    history: Vec<String>,
    max_history: usize,
    next_history_id: AtomicUsize,
}

impl Cli {
    pub fn new(max_history: usize) -> Self {
        Cli {
            commands: BTreeMap::new(),
            history: Vec::new(),
            max_history,
            next_history_id: AtomicUsize::new(0),
        }
    }

    pub fn register_command(&mut self, name: &str, help: &str, cb: CmdCallback) {
        let cmd = Command { name: name.into(), help: help.into(), callback: cb };
        self.commands.insert(name.into(), cmd);
    }

    pub fn execute_line(&mut self, line: &str) -> Result<String, &'static str> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(String::new());
        }

        if self.history.len() >= self.max_history {
            self.history.remove(0);
        }
        self.history.push(trimmed.into());
        self.next_history_id.fetch_add(1, Ordering::SeqCst);

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        let cmd = parts.get(0).ok_or("empty command")?;
        let args = &parts[1..];

        if *cmd == "help" {
            let mut out = String::new();
            writeln!(&mut out, "Available commands:").ok();
            for (name, c) in self.commands.iter() {
                writeln!(&mut out, "{} - {}", name, c.help).ok();
            }
            return Ok(out);
        }

        if let Some(c) = self.commands.get(*cmd) {
            (c.callback)(args)
        } else {
            Err("command not found")
        }
    }

    pub fn history(&self) -> alloc::vec::Vec<String> {
        let mut h = self.history.clone();
        h.reverse();
        h
    }
}

/// Initialize CLI singleton (idempotent).
pub fn init_cli(max_history: usize) {
    let mut g = CLI_REGISTRY.lock();
    if g.is_none() {
        *g = Some(Cli::new(max_history));
        crate::log_info!("ui: cli initialized");
    }
}

/// Register a command.
pub fn register_command(name: &str, help: &str, cb: CmdCallback) -> Result<(), &'static str> {
    let mut g = CLI_REGISTRY.lock();
    if let Some(ref mut cli) = *g {
        cli.register_command(name, help, cb);
        Ok(())
    } else {
        Err("cli not initialized")
    }
}

/// Execute a line through global CLI.
pub fn execute(line: &str) -> Result<String, &'static str> {
    let mut g = CLI_REGISTRY.lock();
    if let Some(ref mut cli) = *g {
        cli.execute_line(line)
    } else {
        Err("cli not initialized")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        init_cli(8);
        let _ = register_command("echo", "Echo", Box::new(|args| {
            let mut out = String::new();
            for a in args { out.push_str(a); out.push(' '); }
            Ok(out)
        }));
        let res = execute("echo hi").unwrap();
        assert!(res.contains("hi"));
    }
}
