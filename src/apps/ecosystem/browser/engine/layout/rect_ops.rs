use super::types::{Rect, EdgeSizes, Dimensions};

impl Rect {
    pub fn expanded_by(self, edge: EdgeSizes) -> Rect {
        Rect {
            x: self.x - edge.left,
            y: self.y - edge.top,
            width: self.width + edge.left + edge.right,
            height: self.height + edge.top + edge.bottom,
        }
    }
}

impl Dimensions {
    pub fn padding_box(&self) -> Rect {
        self.content.expanded_by(self.padding)
    }

    pub fn border_box(&self) -> Rect {
        self.padding_box().expanded_by(self.border)
    }

    pub fn margin_box(&self) -> Rect {
        self.border_box().expanded_by(self.margin)
    }

    pub fn total_horizontal(&self) -> f32 {
        self.margin.left + self.border.left + self.padding.left
            + self.padding.right + self.border.right + self.margin.right
    }

    pub fn total_vertical(&self) -> f32 {
        self.margin.top + self.border.top + self.padding.top
            + self.padding.bottom + self.border.bottom + self.margin.bottom
    }
}

impl EdgeSizes {
    pub fn horizontal(&self) -> f32 {
        self.left + self.right
    }

    pub fn vertical(&self) -> f32 {
        self.top + self.bottom
    }
}
