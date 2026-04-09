use super::super::dom::NodeId;

pub struct FocusManager {
    pub active_element: Option<NodeId>,
}

impl FocusManager {
    pub fn new() -> Self {
        Self { active_element: None }
    }

    pub fn focus(&mut self, node: NodeId) -> FocusChange {
        let prev = self.active_element;
        self.active_element = Some(node);
        FocusChange { blurred: prev, focused: Some(node) }
    }

    pub fn blur(&mut self) -> FocusChange {
        let prev = self.active_element;
        self.active_element = None;
        FocusChange { blurred: prev, focused: None }
    }

    pub fn is_focused(&self, node: NodeId) -> bool {
        self.active_element == Some(node)
    }
}

pub struct FocusChange {
    pub blurred: Option<NodeId>,
    pub focused: Option<NodeId>,
}
