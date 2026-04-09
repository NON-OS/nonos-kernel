use super::types::DomEvent;
use super::super::dom::NodeId;

#[derive(Debug, Clone)]
pub struct MouseEvent {
    pub base: DomEvent,
    pub client_x: f32,
    pub client_y: f32,
    pub button: u8,
    pub buttons: u16,
}

impl MouseEvent {
    pub fn click(target: NodeId, x: f32, y: f32) -> Self {
        Self {
            base: DomEvent::new("click", target, true, true),
            client_x: x,
            client_y: y,
            button: 0,
            buttons: 1,
        }
    }

    pub fn mousedown(target: NodeId, x: f32, y: f32, button: u8) -> Self {
        Self {
            base: DomEvent::new("mousedown", target, true, true),
            client_x: x,
            client_y: y,
            button,
            buttons: 1 << button,
        }
    }

    pub fn mouseup(target: NodeId, x: f32, y: f32, button: u8) -> Self {
        Self {
            base: DomEvent::new("mouseup", target, true, true),
            client_x: x,
            client_y: y,
            button,
            buttons: 0,
        }
    }
}
