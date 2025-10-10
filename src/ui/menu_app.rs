// src/ui/menu_app.rs
#![allow(dead_code)]

use crate::gfx::Fb;
use crate::ui::keyboard::poll_event;
use crate::ui::menu::Menu;

#[derive(Clone, Copy, Debug)]
pub enum MenuAction { StartDemo, SystemInfo, Reboot }

pub struct MenuApp<'a> {
    menu: Menu<'a>,
    first_draw: bool,
}

impl<'a> MenuApp<'a> {
    pub fn new() -> Self {
        // Static items so Menu can borrow 'static
        static ITEMS: [&str; 3] = ["Start Demo", "System Info", "Reboot (hlt)"];
        Self {
            menu: Menu::new("NONOS • MENU", &ITEMS),
            first_draw: true,
        }
    }

    /// Pump input and draw. Returns Some(action) when Enter is hit.
    pub fn pump(&mut self, fb: &Fb) -> Option<MenuAction> {
        // Drain all pending key events
        while let Some(ev) = poll_event() {
            if let Some(idx) = self.menu.handle(ev) {
                let a = match idx {
                    0 => MenuAction::StartDemo,
                    1 => MenuAction::SystemInfo,
                    _ => MenuAction::Reboot,
                };
                return Some(a);
            }
        }

        // Draw (only if dirty; first frame forces)
        unsafe { self.menu.draw(fb, self.first_draw); }
        self.first_draw = false;

        None
    }
}

// impl MenuAction {
//     /// Day-1 behavior: log to serial; Reboot halts.
//     pub fn execute(self) {
//         match self {
//             MenuAction::StartDemo => {
//                 crate::log::logger::debug!("[menu] Start Demo selected");
//             }
//             MenuAction::SystemInfo => {
//                 crate::log::logger::debug!("[menu] System Info selected");
//             }
//             MenuAction::Reboot => {
//                 crate::log::logger::debug!("[menu] Reboot (hlt) selected — halting CPU");
//                 unsafe { loop { core::arch::asm!("hlt"); } }
//             }
//         }
//     }
// }
