use super::super::dom::NodeId;
use super::super::layout::types::LayoutBox;

pub fn hit_test(layout_box: &LayoutBox, x: f32, y: f32) -> Option<u32> {
    for child in layout_box.children.iter().rev() {
        if let Some(id) = hit_test(child, x, y) {
            return Some(id);
        }
    }

    let bb = layout_box.dimensions.border_box();
    if x >= bb.x && x <= bb.x + bb.width && y >= bb.y && y <= bb.y + bb.height {
        return layout_box.node_index;
    }

    None
}

pub fn hit_test_to_node_id(layout_box: &LayoutBox, x: f32, y: f32) -> Option<NodeId> {
    hit_test(layout_box, x, y).map(NodeId)
}
