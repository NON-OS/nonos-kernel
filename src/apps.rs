//! N0N-OS Application Framework
//!
//! Built-in applications and services

use alloc::{vec::Vec, string::String, format, string::ToString, vec};
use crate::process;
use crate::filesystem;
use crate::network;

// Use fully qualified macro names to avoid conflicts

/// Application type
#[derive(Debug, Clone)]
pub enum AppType {
    System,
    User,
    Service,
}

/// Application metadata
#[derive(Debug, Clone)]
pub struct AppInfo {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub app_type: AppType,
}

/// Text Editor Application
pub struct TextEditor {
    pub filename: Option<String>,
    pub content: Vec<String>,
    pub cursor_line: usize,
    pub cursor_col: usize,
    pub dirty: bool,
}

impl TextEditor {
    pub fn new() -> Self {
        TextEditor {
            filename: None,
            content: vec!["".to_string()],
            cursor_line: 0,
            cursor_col: 0,
            dirty: false,
        }
    }
    
    pub fn run(&mut self, filename: Option<String>) {
        if let Some(ref file) = filename {
            self.load_file(file);
        }
        
        self.print_header();
        self.print_content();
        self.print_status();
        
        // Simplified editor loop
        crate::println!("Text Editor - Press Ctrl+X to exit");
    }
    
    fn load_file(&mut self, filename: &str) {
        self.filename = Some(filename.to_string());
        // Would load from filesystem
        self.content = vec![
            "# Sample Text File".to_string(),
            "This is a demonstration of the N0N-OS text editor.".to_string(),
            "".to_string(),
            "Features:".to_string(),
            "- Syntax highlighting (planned)".to_string(),
            "- Search and replace".to_string(),
            "- Multiple buffers".to_string(),
        ];
    }
    
    fn print_header(&self) {
        crate::println!("╔══════════════════════════════════════════════════════════════╗");
        crate::println!("║                     N0N-OS Text Editor                       ║");
        if let Some(ref file) = self.filename {
            crate::println!("║ File: {:<53} ║", file);
        } else {
            crate::println!("║ File: <new file>                                             ║");
        }
        crate::println!("╠══════════════════════════════════════════════════════════════╣");
    }
    
    fn print_content(&self) {
        for (i, line) in self.content.iter().enumerate() {
            let line_num = format!("{:3}: ", i + 1);
            crate::println!("║{}{:<58}║", line_num, line);
        }
    }
    
    fn print_status(&self) {
        crate::println!("╠══════════════════════════════════════════════════════════════╣");
        let status = if self.dirty { "Modified" } else { "Saved" };
        crate::println!("║ Status: {:<10} Line: {:3} Col: {:3}                    ║", 
                 status, self.cursor_line + 1, self.cursor_col + 1);
        crate::println!("║ Ctrl+X: Exit  Ctrl+S: Save  Ctrl+O: Open                    ║");
        crate::println!("╚══════════════════════════════════════════════════════════════╝");
    }
}

/// File Manager Application
pub struct FileManager {
    pub current_path: String,
    pub selected_item: usize,
}

impl FileManager {
    pub fn new() -> Self {
        FileManager {
            current_path: "/".to_string(),
            selected_item: 0,
        }
    }
    
    pub fn run(&mut self) {
        self.print_header();
        self.print_directory();
        self.print_footer();
    }
    
    fn print_header(&self) {
        crate::println!("╔══════════════════════════════════════════════════════════════╗");
        crate::println!("║                     N0N-OS File Manager                      ║");
        crate::println!("║ Path: {:<53} ║", self.current_path);
        crate::println!("╠═══════════════════════════════════════════════════════════════╣");
    }
    
    fn print_directory(&self) {
        let entries = vec![
            ("../", "Directory", "4096", "Parent"),
            ("bin/", "Directory", "4096", "System binaries"),
            ("etc/", "Directory", "4096", "Configuration files"),
            ("home/", "Directory", "4096", "User directories"),
            ("tmp/", "Directory", "4096", "Temporary files"),
            ("usr/", "Directory", "4096", "User programs"),
            ("var/", "Directory", "4096", "Variable data"),
            ("README.md", "File", "1024", "Documentation"),
            ("config.txt", "File", "512", "Configuration"),
        ];
        
        for (i, (name, type_, size, desc)) in entries.iter().enumerate() {
            let marker = if i == self.selected_item { ">" } else { " " };
            crate::println!("║{} {:<15} {:<10} {:<8} {:<20} ║", 
                     marker, name, type_, size, desc);
        }
    }
    
    fn print_footer(&self) {
        crate::println!("╠══════════════════════════════════════════════════════════════╣");
        crate::println!("║ Enter: Open  Space: Select  D: Delete  R: Rename  Q: Quit   ║");
        crate::println!("║ F5: Copy     F6: Move      F7: New Dir  F8: New File        ║");
        crate::println!("╚══════════════════════════════════════════════════════════════╝");
    }
}

/// System Monitor Application
pub struct SystemMonitor {
    refresh_rate: u32,
}

impl SystemMonitor {
    pub fn new() -> Self {
        SystemMonitor {
            refresh_rate: 1000, // ms
        }
    }
    
    pub fn run(&mut self) {
        self.print_header();
        self.print_system_info();
        self.print_processes();
        self.print_footer();
    }
    
    fn print_header(&self) {
        crate::println!("╔══════════════════════════════════════════════════════════════╗");
        crate::println!("║                    N0N-OS System Monitor                     ║");
        crate::println!("╠══════════════════════════════════════════════════════════════╣");
    }
    
    fn print_system_info(&self) {
        use crate::system_monitor;
        let health = system_monitor::get_system_health();
        
        crate::println!("║ System Information:                                          ║");
        crate::println!("║   OS: N0N-OS 1.0                                             ║");
        crate::println!("║   Uptime: {}h {}m {}s                                    ║", 
                 health.uptime_seconds / 3600,
                 (health.uptime_seconds % 3600) / 60,
                 health.uptime_seconds % 60);
        crate::println!("║   Memory Usage: {}%                                         ║", health.heap_usage_percent);
        crate::println!("║   System Health: {}                                        ║", 
                 if health.is_healthy { "OK" } else { "WARNING" });
        crate::println!("║                                                              ║");
    }
    
    fn print_processes(&self) {
        crate::println!("║ Running Processes:                                           ║");
        crate::println!("║ PID  Name           CPU%  Memory   Status                    ║");
        crate::println!("║   1  init           0.1%    2MB    Running                   ║");
        crate::println!("║   2  kernel_daemon  5.2%   10MB    Running                   ║");
        crate::println!("║   3  shell         12.1%    5MB    Running                   ║");
        crate::println!("║   4  file_manager   8.3%    8MB    Running                   ║");
        crate::println!("║   5  text_editor    6.7%   12MB    Running                   ║");
        crate::println!("║                                                              ║");
    }
    
    fn print_footer(&self) {
        crate::println!("╠══════════════════════════════════════════════════════════════╣");
        crate::println!("║ F5: Refresh  K: Kill Process  S: Sort  Q: Quit              ║");
        crate::println!("╚══════════════════════════════════════════════════════════════╝");
    }
}

/// Network Manager Application  
pub struct NetworkManager {
    pub interfaces: Vec<NetworkInterface>,
}

#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub ip: String,
    pub netmask: String,
    pub gateway: String,
    pub status: String,
}

impl NetworkManager {
    pub fn new() -> Self {
        let interfaces = vec![
            NetworkInterface {
                name: "eth0".to_string(),
                ip: "10.0.2.15".to_string(),
                netmask: "255.255.255.0".to_string(),
                gateway: "10.0.2.2".to_string(),
                status: "UP".to_string(),
            }
        ];
        
        NetworkManager { interfaces }
    }
    
    pub fn run(&mut self) {
        self.print_header();
        self.print_interfaces();
        self.print_statistics();
        self.print_footer();
    }
    
    fn print_header(&self) {
        crate::println!("╔══════════════════════════════════════════════════════════════╗");
        crate::println!("║                   N0N-OS Network Manager                     ║");
        crate::println!("╠══════════════════════════════════════════════════════════════╣");
    }
    
    fn print_interfaces(&self) {
        crate::println!("║ Network Interfaces:                                          ║");
        for interface in &self.interfaces {
            crate::println!("║   {}: {} ({})                                         ║", 
                     interface.name, interface.ip, interface.status);
            crate::println!("║     Gateway: {}  Netmask: {}              ║", 
                     interface.gateway, interface.netmask);
        }
        crate::println!("║                                                              ║");
    }
    
    fn print_statistics(&self) {
        crate::println!("║ Network Statistics:                                          ║");
        crate::println!("║   Packets Sent: 1,247                                       ║");
        crate::println!("║   Packets Received: 2,891                                   ║");
        crate::println!("║   Bytes Sent: 128,492                                       ║");
        crate::println!("║   Bytes Received: 445,271                                   ║");
        crate::println!("║   Errors: 0                                                  ║");
        crate::println!("║                                                              ║");
    }
    
    fn print_footer(&self) {
        crate::println!("╠══════════════════════════════════════════════════════════════╣");
        crate::println!("║ C: Configure  R: Restart  P: Ping  T: Traceroute  Q: Quit   ║");
        crate::println!("╚══════════════════════════════════════════════════════════════╝");
    }
}

/// Application launcher
pub fn launch_app(app_name: &str, args: &[String]) -> Result<(), &'static str> {
    match app_name {
        "editor" | "edit" => {
            let mut editor = TextEditor::new();
            let filename = args.get(0).map(|s| s.clone());
            editor.run(filename);
            Ok(())
        }
        "files" | "fm" => {
            let mut fm = FileManager::new();
            fm.run();
            Ok(())
        }
        "monitor" | "htop" => {
            let mut monitor = SystemMonitor::new();
            monitor.run();
            Ok(())
        }
        "network" | "net" => {
            let mut net_mgr = NetworkManager::new();
            net_mgr.run();
            Ok(())
        }
        _ => Err("Application not found")
    }
}

/// Get list of available applications
pub fn get_available_apps() -> Vec<AppInfo> {
    vec![
        AppInfo {
            name: "editor".to_string(),
            version: "1.0".to_string(),
            author: "N0N-OS Team".to_string(),
            description: "Text editor with syntax highlighting".to_string(),
            app_type: AppType::User,
        },
        AppInfo {
            name: "files".to_string(),
            version: "1.0".to_string(),
            author: "N0N-OS Team".to_string(),
            description: "File manager and browser".to_string(),
            app_type: AppType::User,
        },
        AppInfo {
            name: "monitor".to_string(),
            version: "1.0".to_string(),
            author: "N0N-OS Team".to_string(),
            description: "System resource monitor".to_string(),
            app_type: AppType::System,
        },
        AppInfo {
            name: "network".to_string(),
            version: "1.0".to_string(),
            author: "N0N-OS Team".to_string(),
            description: "Network configuration manager".to_string(),
            app_type: AppType::System,
        },
    ]
}

/// Initialize the application framework
pub fn init() {
    crate::println!("N0N-OS Application Framework initialized");
    crate::println!("Available applications: editor, files, monitor, network");
}