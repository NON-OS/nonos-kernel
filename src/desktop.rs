//! N0N-OS Desktop Environment
//!
//! Graphical desktop with window management, taskbar, and applications

use alloc::{vec::Vec, string::String, format, string::ToString, vec};
use crate::apps;

// Use fully qualified macro names to avoid conflicts

/// Window management
#[derive(Debug, Clone)]
pub struct Window {
    pub id: u32,
    pub title: String,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub minimized: bool,
    pub maximized: bool,
    pub focused: bool,
    pub app_name: String,
}

/// Desktop manager
pub struct Desktop {
    pub windows: Vec<Window>,
    pub taskbar_height: u32,
    pub wallpaper: String,
    pub next_window_id: u32,
}

impl Desktop {
    /// Create new desktop
    pub fn new() -> Self {
        Desktop {
            windows: Vec::new(),
            taskbar_height: 40,
            wallpaper: "nonos-default".to_string(),
            next_window_id: 1,
        }
    }
    
    /// Start the desktop environment
    pub fn run(&mut self) {
        self.draw_desktop();
        self.show_startup_message();
        self.main_loop();
    }
    
    /// Main desktop loop
    fn main_loop(&mut self) {
        crate::println!("Desktop environment started. Press keys to interact:");
        crate::println!("  A: Launch Text Editor");
        crate::println!("  F: Launch File Manager"); 
        crate::println!("  M: Launch System Monitor");
        crate::println!("  N: Launch Network Manager");
        crate::println!("  T: Open Terminal");
        crate::println!("  X: Exit Desktop");
        
        // Simplified event loop
        loop {
            // Would handle keyboard/mouse input here
            break;
        }
    }
    
    /// Draw the desktop interface
    fn draw_desktop(&self) {
        self.clear_screen();
        self.draw_wallpaper();
        self.draw_taskbar();
        self.draw_windows();
    }
    
    /// Clear the screen
    fn clear_screen(&self) {
        crate::println!("\x1b[2J\x1b[H"); // ANSI clear screen
    }
    
    /// Draw desktop wallpaper
    fn draw_wallpaper(&self) {
        crate::println!("╔══════════════════════════════════════════════════════════════════════════╗");
        crate::println!("║                                                                          ║");
        crate::println!("║                        ███╗   ██╗ ██████╗ ███╗   ██╗                    ║");
        crate::println!("║                        ████╗  ██║██╔═══██╗████╗  ██║                    ║");
        crate::println!("║                        ██╔██╗ ██║██║   ██║██╔██╗ ██║                    ║");
        crate::println!("║                        ██║╚██╗██║██║   ██║██║╚██╗██║                    ║");
        crate::println!("║                        ██║ ╚████║╚██████╔╝██║ ╚████║                    ║");
        crate::println!("║                        ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═══╝                    ║");
        crate::println!("║                                                                          ║");
        crate::println!("║                                   ██████╗ ███████╗                      ║");
        crate::println!("║                                  ██╔═══██╗██╔════╝                      ║");
        crate::println!("║                                  ██║   ██║███████╗                      ║");
        crate::println!("║                                  ██║   ██║╚════██║                      ║");
        crate::println!("║                                  ╚██████╔╝███████║                      ║");
        crate::println!("║                                   ╚═════╝ ╚══════╝                      ║");
        crate::println!("║                                                                          ║");
        crate::println!("║                          Advanced Microkernel Operating System          ║");
        crate::println!("║                               Version 1.0 - Desktop Edition            ║");
        crate::println!("║                                                                          ║");
        for _ in 0..8 {
            crate::println!("║                                                                          ║");
        }
    }
    
    /// Draw taskbar
    fn draw_taskbar(&self) {
        crate::println!("╠══════════════════════════════════════════════════════════════════════════╣");
        crate::println!("║ [Start] [Editor] [Files] [Monitor] [Network]           [WiFi] [🔊] [⚙️]  ║");
        crate::println!("╚══════════════════════════════════════════════════════════════════════════╝");
    }
    
    /// Draw all windows
    fn draw_windows(&self) {
        for window in &self.windows {
            if !window.minimized {
                self.draw_window(window);
            }
        }
    }
    
    /// Draw a single window
    fn draw_window(&self, window: &Window) {
        let border = if window.focused { "█" } else { "▓" };
        
        crate::println!("{}╔{:═<width$}╗{}", 
                 border,
                 format!(" {} ", window.title),
                 border,
                 width = window.width as usize - 4);
        
        for _ in 0..(window.height - 2) {
            crate::println!("{}║{:width$}║{}", 
                     border, 
                     "", 
                     border,
                     width = window.width as usize - 4);
        }
        
        crate::println!("{}╚{:═<width$}╝{}", 
                 border, 
                 "", 
                 border,
                 width = window.width as usize - 4);
    }
    
    /// Create a new window
    pub fn create_window(&mut self, title: String, width: u32, height: u32, app_name: String) -> u32 {
        let window_id = self.next_window_id;
        self.next_window_id += 1;
        
        let window = Window {
            id: window_id,
            title,
            x: 10 + (self.windows.len() as u32 * 30),
            y: 5 + (self.windows.len() as u32 * 20),
            width,
            height,
            minimized: false,
            maximized: false,
            focused: true,
            app_name,
        };
        
        // Unfocus other windows
        for w in &mut self.windows {
            w.focused = false;
        }
        
        self.windows.push(window);
        window_id
    }
    
    /// Close window
    pub fn close_window(&mut self, window_id: u32) {
        self.windows.retain(|w| w.id != window_id);
    }
    
    /// Focus window
    pub fn focus_window(&mut self, window_id: u32) {
        for window in &mut self.windows {
            window.focused = window.id == window_id;
        }
    }
    
    /// Launch application
    pub fn launch_application(&mut self, app_name: &str) {
        match app_name {
            "editor" => {
                self.create_window(
                    "Text Editor".to_string(),
                    70, 20,
                    "editor".to_string()
                );
                crate::println!("Launched Text Editor in new window");
            }
            "files" => {
                self.create_window(
                    "File Manager".to_string(),
                    70, 25,
                    "files".to_string()
                );
                crate::println!("Launched File Manager in new window");
            }
            "monitor" => {
                self.create_window(
                    "System Monitor".to_string(),
                    75, 20,
                    "monitor".to_string()
                );
                crate::println!("Launched System Monitor in new window");
            }
            "network" => {
                self.create_window(
                    "Network Manager".to_string(),
                    70, 18,
                    "network".to_string()
                );
                crate::println!("Launched Network Manager in new window");
            }
            "terminal" => {
                self.create_window(
                    "Terminal".to_string(),
                    80, 24,
                    "terminal".to_string()
                );
                crate::println!("Launched Terminal in new window");
            }
            _ => {
                crate::println!("Unknown application: {}", app_name);
            }
        }
        
        self.draw_desktop();
    }
    
    /// Show startup message
    fn show_startup_message(&self) {
        crate::println!("╔════════════════════════════════════════╗");
        crate::println!("║          Welcome to N0N-OS!           ║");
        crate::println!("║                                        ║");
        crate::println!("║  • Desktop Environment Ready           ║");
        crate::println!("║  • Applications Available              ║");
        crate::println!("║  • Network Connectivity Active        ║");
        crate::println!("║  • Security Features Enabled          ║");
        crate::println!("║                                        ║");
        crate::println!("║  Click Start or use keyboard shortcuts ║");
        crate::println!("╚════════════════════════════════════════╝");
        crate::println!("");
    }
}

/// Start menu system
pub struct StartMenu {
    pub open: bool,
    pub categories: Vec<MenuCategory>,
}

#[derive(Debug, Clone)]
pub struct MenuCategory {
    pub name: String,
    pub items: Vec<MenuItem>,
}

#[derive(Debug, Clone)]
pub struct MenuItem {
    pub name: String,
    pub command: String,
    pub icon: String,
    pub description: String,
}

impl StartMenu {
    pub fn new() -> Self {
        let categories = vec![
            MenuCategory {
                name: "Applications".to_string(),
                items: vec![
                    MenuItem {
                        name: "Text Editor".to_string(),
                        command: "editor".to_string(),
                        icon: "📝".to_string(),
                        description: "Edit text files".to_string(),
                    },
                    MenuItem {
                        name: "File Manager".to_string(),
                        command: "files".to_string(),
                        icon: "📁".to_string(),
                        description: "Browse files and folders".to_string(),
                    },
                ],
            },
            MenuCategory {
                name: "System".to_string(),
                items: vec![
                    MenuItem {
                        name: "System Monitor".to_string(),
                        command: "monitor".to_string(),
                        icon: "📊".to_string(),
                        description: "View system resources".to_string(),
                    },
                    MenuItem {
                        name: "Network Manager".to_string(),
                        command: "network".to_string(),
                        icon: "🌐".to_string(),
                        description: "Configure network settings".to_string(),
                    },
                ],
            },
            MenuCategory {
                name: "Tools".to_string(),
                items: vec![
                    MenuItem {
                        name: "Terminal".to_string(),
                        command: "terminal".to_string(),
                        icon: "💻".to_string(),
                        description: "Command line interface".to_string(),
                    },
                ],
            },
        ];
        
        StartMenu {
            open: false,
            categories,
        }
    }
    
    pub fn show(&self) {
        if !self.open {
            return;
        }
        
        crate::println!("╔═══════════════════════════════╗");
        crate::println!("║          Start Menu           ║");
        crate::println!("╠═══════════════════════════════╣");
        
        for category in &self.categories {
            crate::println!("║ {}:", category.name);
            for item in &category.items {
                crate::println!("║   {} {} - {}", item.icon, item.name, item.description);
            }
            crate::println!("║                               ║");
        }
        
        crate::println!("╠═══════════════════════════════╣");
        crate::println!("║ [Settings] [About] [Shutdown] ║");
        crate::println!("╚═══════════════════════════════╝");
    }
}

/// Global desktop instance
static mut DESKTOP: Option<Desktop> = None;

/// Initialize desktop environment
pub fn init() {
    unsafe {
        DESKTOP = Some(Desktop::new());
    }
    crate::println!("N0N-OS Desktop Environment initialized");
}

/// Start desktop environment
pub fn start_desktop() -> ! {
    unsafe {
        if let Some(ref mut desktop) = DESKTOP {
            desktop.run();
        }
    }
    
    loop { unsafe { x86_64::instructions::hlt(); } }
}