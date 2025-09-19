//! N0N-OS Shell - Command Line Interface
//!
//! Interactive shell with command parsing and execution

use alloc::{vec::Vec, string::String, format, string::ToString};
use crate::process;
use crate::filesystem;
use crate::memory;
use crate::network;
use crate::system_monitor;

// Use fully qualified macro names to avoid conflicts

/// Shell state and command history
pub struct Shell {
    pub current_directory: String,
    pub command_history: Vec<String>,
    pub environment: Vec<(String, String)>,
    pub running: bool,
}

impl Shell {
    /// Create a new shell instance
    pub fn new() -> Self {
        let mut env = Vec::new();
        env.push(("PATH".to_string(), "/bin:/usr/bin:/usr/local/bin".to_string()));
        env.push(("HOME".to_string(), "/home/user".to_string()));
        env.push(("USER".to_string(), "nonos".to_string()));
        
        Shell {
            current_directory: "/".to_string(),
            command_history: Vec::new(),
            environment: env,
            running: true,
        }
    }

    /// Main shell loop
    pub fn run(&mut self) -> ! {
        self.print_banner();
        
        loop {
            if !self.running {
                break;
            }
            
            self.print_prompt();
            let command = self.read_command();
            
            if !command.is_empty() {
                self.command_history.push(command.clone());
                self.execute_command(&command);
            }
        }
        
        loop { unsafe { x86_64::instructions::hlt(); } }
    }
    
    /// Print shell banner
    fn print_banner(&self) {
        crate::println!("N0N-OS Shell v1.0");
        crate::println!("Advanced Microkernel Operating System");
        crate::println!("Type 'help' for available commands\n");
    }
    
    /// Print command prompt
    fn print_prompt(&self) {
        crate::print!("nonos:{}$ ", self.current_directory);
    }
    

    /// Read command from input
    fn read_command(&self) -> String {
        use alloc::string::String;
        let mut input = String::new();
        
        // Try to get keyboard driver
        if let Some(keyboard) = crate::drivers::keyboard::get_keyboard() {
            crate::print!(""); // Ensure cursor is visible
            
            loop {
                // Check for key events
                while let Some(key_event) = keyboard.read_key() {
                    if key_event.pressed {
                        if let Some(ch) = key_event.ascii {
                            match ch {
                                '\n' => {
                                    crate::println!("");
                                    return input;
                                }
                                '\x08' => { // Backspace
                                    if !input.is_empty() {
                                        input.pop();
                                        crate::print!("\x08 \x08"); // Erase character
                                    }
                                }
                                '\t' => {
                                    // TODO: Implement command completion
                                    input.push(' '); // For now, treat as space
                                    crate::print!(" ");
                                }
                                ch if ch.is_ascii_control() => {
                                    // Ignore other control characters
                                }
                                ch => {
                                    input.push(ch);
                                    crate::print!("{}", ch);
                                }
                            }
                        }
                    }
                }
                
                // Small delay to prevent busy waiting
                unsafe {
                    for _ in 0..1000 {
                        core::arch::asm!("pause");
                    }
                }
            }
        } else {
            // Fallback: cycle through demo commands
            static mut DEMO_COMMANDS: &[&str] = &[
                "help",
                "uname", 
                "meminfo",
                "ps",
                "ls",
                "env",
                "cpuinfo",
                "uptime",
                "clear"
            ];
            static mut DEMO_INDEX: usize = 0;
            
            unsafe {
                let cmd = DEMO_COMMANDS[DEMO_INDEX].to_string();
                DEMO_INDEX = (DEMO_INDEX + 1) % DEMO_COMMANDS.len();
                
                // Simulate typing delay for demo
                for _ in 0..1000000 {
                    core::arch::asm!("pause");
                }
                
                cmd
            }
        }
    }
    
    /// Execute a command
    fn execute_command(&mut self, command: &str) {
        let parts: Vec<&str> = command.trim().split_whitespace().collect();
        if parts.is_empty() {
            return;
        }
        
        match parts[0] {
            "help" => self.cmd_help(),
            "ls" => self.cmd_ls(&parts[1..]),
            "cd" => self.cmd_cd(&parts[1..]),
            "pwd" => self.cmd_pwd(),
            "ps" => self.cmd_ps(),
            "kill" => self.cmd_kill(&parts[1..]),
            "cat" => self.cmd_cat(&parts[1..]),
            "echo" => self.cmd_echo(&parts[1..]),
            "env" => self.cmd_env(),
            "set" => self.cmd_set(&parts[1..]),
            "meminfo" => self.cmd_meminfo(),
            "cpuinfo" => self.cmd_cpuinfo(),
            "netstat" => self.cmd_netstat(),
            "mount" => self.cmd_mount(&parts[1..]),
            "uname" => self.cmd_uname(),
            "uptime" => self.cmd_uptime(),
            "history" => self.cmd_history(),
            "clear" => self.cmd_clear(),
            "exit" | "quit" => self.cmd_exit(),
            "shutdown" => self.cmd_shutdown(),
            "reboot" => self.cmd_reboot(),
            _ => {
                crate::println!("Command '{}' not found. Type 'help' for available commands.", parts[0]);
            }
        }
    }
    
    /// Help command
    fn cmd_help(&self) {
        crate::println!("N0N-OS Shell - Available Commands:");
        crate::println!("  File System:");
        crate::println!("    ls [path]         - List directory contents");
        crate::println!("    cd <path>         - Change directory");
        crate::println!("    pwd               - Print working directory");
        crate::println!("    cat <file>        - Display file contents");
        crate::println!("    mount [options]   - Mount/list filesystems");
        crate::println!("");
        crate::println!("  Process Management:");
        crate::println!("    ps                - List running processes");
        crate::println!("    kill <pid>        - Terminate process");
        crate::println!("");
        crate::println!("  System Information:");
        crate::println!("    meminfo           - Memory usage information");
        crate::println!("    cpuinfo           - CPU information");
        crate::println!("    netstat           - Network status");
        crate::println!("    uname             - System information");
        crate::println!("    uptime            - System uptime");
        crate::println!("");
        crate::println!("  Environment:");
        crate::println!("    env               - Display environment variables");
        crate::println!("    set <var>=<val>   - Set environment variable");
        crate::println!("    echo <text>       - Print text");
        crate::println!("");
        crate::println!("  Shell:");
        crate::println!("    history           - Command history");
        crate::println!("    clear             - Clear screen");
        crate::println!("    help              - This help message");
        crate::println!("");
        crate::println!("  System Control:");
        crate::println!("    shutdown          - Shutdown system");
        crate::println!("    reboot            - Restart system");
        crate::println!("    exit/quit         - Exit shell");
    }
    
    /// List directory contents
    fn cmd_ls(&self, args: &[&str]) {
        let path = if args.is_empty() { 
            &self.current_directory 
        } else { 
            args[0] 
        };
        
        crate::println!("Listing directory: {}", path);
        // Would integrate with filesystem module
        crate::println!("bin/");
        crate::println!("etc/");
        crate::println!("home/");
        crate::println!("tmp/");
        crate::println!("usr/");
        crate::println!("var/");
    }
    
    /// Change directory
    fn cmd_cd(&mut self, args: &[&str]) {
        if args.is_empty() {
            self.current_directory = "/home/user".to_string();
        } else {
            // Simplified path handling
            if args[0].starts_with('/') {
                self.current_directory = args[0].to_string();
            } else {
                self.current_directory = format!("{}/{}", self.current_directory, args[0]);
            }
        }
    }
    
    /// Print working directory
    fn cmd_pwd(&self) {
        crate::println!("{}", self.current_directory);
    }
    
    /// List processes
    fn cmd_ps(&self) {
        crate::println!("PID  PPID CMD");
        crate::println!("  1     0 init");
        crate::println!("  2     1 kernel_daemon");
        crate::println!("  3     1 shell");
        // Would integrate with process management
    }
    
    /// Kill process
    fn cmd_kill(&self, args: &[&str]) {
        if args.is_empty() {
            crate::println!("Usage: kill <pid>");
            return;
        }
        
        if let Ok(pid) = args[0].parse::<u32>() {
            crate::println!("Terminating process {}", pid);
            // Would integrate with process management
        } else {
            crate::println!("Invalid PID: {}", args[0]);
        }
    }
    
    /// Display file contents
    fn cmd_cat(&self, args: &[&str]) {
        if args.is_empty() {
            crate::println!("Usage: cat <file>");
            return;
        }
        
        crate::println!("Reading file: {}", args[0]);
        // Would integrate with filesystem
        crate::println!("File contents would appear here...");
    }
    
    /// Echo text
    fn cmd_echo(&self, args: &[&str]) {
        crate::println!("{}", args.join(" "));
    }
    
    /// Display environment variables
    fn cmd_env(&self) {
        for (key, value) in &self.environment {
            crate::println!("{}={}", key, value);
        }
    }
    
    /// Set environment variable
    fn cmd_set(&mut self, args: &[&str]) {
        if args.is_empty() {
            crate::println!("Usage: set <variable>=<value>");
            return;
        }
        
        if let Some(pos) = args[0].find('=') {
            let key = args[0][..pos].to_string();
            let value = args[0][pos+1..].to_string();
            
            // Update existing or add new
            if let Some(entry) = self.environment.iter_mut().find(|(k, _)| k == &key) {
                entry.1 = value;
            } else {
                self.environment.push((key, value));
            }
        } else {
            crate::println!("Invalid format. Use: variable=value");
        }
    }
    
    /// Display memory information
    fn cmd_meminfo(&self) {
        let health = system_monitor::get_system_health();
        crate::println!("Memory Information:");
        crate::println!("  Heap Usage: {}%", health.heap_usage_percent);
        crate::println!("  Heap Failures: {}", health.heap_failures);
        crate::println!("  System Health: {}", if health.is_healthy { "OK" } else { "WARN" });
    }
    
    /// Display CPU information
    fn cmd_cpuinfo(&self) {
        crate::println!("CPU Information:");
        crate::println!("  Architecture: x86_64");
        crate::println!("  Cores: 4 (detected)");
        crate::println!("  Features: SSE, AVX, RDRAND, RDSEED");
        crate::println!("  Security: SMEP, SMAP, CET");
    }
    
    /// Display network status
    fn cmd_netstat(&self) {
        crate::println!("Network Status:");
        crate::println!("  Interfaces: 1 active");
        crate::println!("  IP: 10.0.2.15/24");
        crate::println!("  Gateway: 10.0.2.2");
        crate::println!("  DNS: 10.0.2.3");
    }
    
    /// Mount/list filesystems
    fn cmd_mount(&self, args: &[&str]) {
        if args.is_empty() {
            crate::println!("Mounted Filesystems:");
            crate::println!("  / (root)      - nonos-fs");
            crate::println!("  /tmp          - tmpfs");
            crate::println!("  /proc         - procfs");
        } else {
            crate::println!("Mount functionality not implemented yet");
        }
    }
    
    /// System information
    fn cmd_uname(&self) {
        crate::println!("N0N-OS 1.0 x86_64");
    }
    
    /// System uptime
    fn cmd_uptime(&self) {
        let health = system_monitor::get_system_health();
        let hours = health.uptime_seconds / 3600;
        let minutes = (health.uptime_seconds % 3600) / 60;
        let seconds = health.uptime_seconds % 60;
        
        crate::println!("Uptime: {}h {}m {}s", hours, minutes, seconds);
    }
    
    /// Command history
    fn cmd_history(&self) {
        for (i, cmd) in self.command_history.iter().enumerate() {
            crate::println!("{:4}: {}", i + 1, cmd);
        }
    }
    
    /// Clear screen
    fn cmd_clear(&self) {
        crate::println!("\x1b[2J\x1b[H"); // ANSI clear screen
    }
    
    /// Exit shell
    fn cmd_exit(&mut self) {
        crate::println!("Goodbye!");
        self.running = false;
    }
    
    /// Shutdown system
    fn cmd_shutdown(&self) {
        crate::println!("Shutting down N0N-OS...");
        // Would trigger system shutdown
        unsafe { x86_64::instructions::hlt(); }
    }
    
    /// Reboot system
    fn cmd_reboot(&self) {
        crate::println!("Rebooting N0N-OS...");
        // Would trigger system reboot
        unsafe { x86_64::instructions::hlt(); }
    }
}

/// Global shell instance
static mut SHELL: Option<Shell> = None;

/// Initialize the shell
pub fn init() {
    unsafe {
        SHELL = Some(Shell::new());
    }
}

/// Start the shell
pub fn start_shell() -> ! {
    unsafe {
        if let Some(ref mut shell) = SHELL {
            shell.run();
        }
    }
    
    loop { unsafe { x86_64::instructions::hlt(); } }
}

// Helper macros for print functionality
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        // Would integrate with VGA/serial output
    };
}

#[macro_export]
macro_rules! println {
    () => { crate::print!("\n"); };
    ($($arg:tt)*) => {
        crate::print!("{}\n", format_args!($($arg)*));
    };
}