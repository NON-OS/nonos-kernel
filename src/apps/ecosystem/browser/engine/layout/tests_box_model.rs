#[cfg(test)]
mod tests {
    use crate::apps::ecosystem::browser::engine::layout::types::*;

    #[test]
    fn test_rect_expanded_by() {
        let r = Rect { x: 10.0, y: 20.0, width: 100.0, height: 50.0 };
        let edge = EdgeSizes { top: 5.0, right: 10.0, bottom: 5.0, left: 10.0 };
        let expanded = r.expanded_by(edge);
        assert!((expanded.x - 0.0).abs() < 0.01);
        assert!((expanded.y - 15.0).abs() < 0.01);
        assert!((expanded.width - 120.0).abs() < 0.01);
        assert!((expanded.height - 60.0).abs() < 0.01);
    }

    #[test]
    fn test_dimensions_padding_box() {
        let mut d = Dimensions::default();
        d.content = Rect { x: 20.0, y: 20.0, width: 100.0, height: 50.0 };
        d.padding = EdgeSizes { top: 10.0, right: 10.0, bottom: 10.0, left: 10.0 };
        let pb = d.padding_box();
        assert!((pb.width - 120.0).abs() < 0.01);
        assert!((pb.height - 70.0).abs() < 0.01);
    }

    #[test]
    fn test_dimensions_border_box() {
        let mut d = Dimensions::default();
        d.content = Rect { x: 30.0, y: 30.0, width: 100.0, height: 50.0 };
        d.padding = EdgeSizes { top: 5.0, right: 5.0, bottom: 5.0, left: 5.0 };
        d.border = EdgeSizes { top: 2.0, right: 2.0, bottom: 2.0, left: 2.0 };
        let bb = d.border_box();
        assert!((bb.width - 114.0).abs() < 0.01);
        assert!((bb.height - 64.0).abs() < 0.01);
    }

    #[test]
    fn test_dimensions_margin_box() {
        let mut d = Dimensions::default();
        d.content = Rect { x: 50.0, y: 50.0, width: 200.0, height: 100.0 };
        d.padding = EdgeSizes { top: 10.0, right: 10.0, bottom: 10.0, left: 10.0 };
        d.border = EdgeSizes { top: 1.0, right: 1.0, bottom: 1.0, left: 1.0 };
        d.margin = EdgeSizes { top: 20.0, right: 20.0, bottom: 20.0, left: 20.0 };
        let mb = d.margin_box();
        assert!((mb.width - 262.0).abs() < 0.01);
        assert!((mb.height - 162.0).abs() < 0.01);
    }

    #[test]
    fn test_total_horizontal() {
        let mut d = Dimensions::default();
        d.margin = EdgeSizes { top: 0.0, right: 10.0, bottom: 0.0, left: 10.0 };
        d.border = EdgeSizes { top: 0.0, right: 2.0, bottom: 0.0, left: 2.0 };
        d.padding = EdgeSizes { top: 0.0, right: 5.0, bottom: 0.0, left: 5.0 };
        assert!((d.total_horizontal() - 34.0).abs() < 0.01);
    }

    #[test]
    fn test_edge_sizes_horizontal() {
        let e = EdgeSizes { top: 1.0, right: 3.0, bottom: 1.0, left: 7.0 };
        assert!((e.horizontal() - 10.0).abs() < 0.01);
        assert!((e.vertical() - 2.0).abs() < 0.01);
    }
}
