//! Inline height-for-width recipient surface. The final child is the editor
//! and receives the unused width of its line. It is never reparented.
use gtk::{glib, prelude::*, subclass::prelude::*};

const GAP: i32 = 3;
const ROW_GAP: i32 = 2;
const EDITOR_MIN: i32 = 100;
const NATURAL_CAP: i32 = 720;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot { x: i32, row: usize, width: i32 }

fn pack(chips: &[i32], editor_min: i32, available: i32) -> Vec<Slot> {
    let width = available.max(1);
    let mut slots = Vec::with_capacity(chips.len() + 1);
    let mut x = 0;
    let mut row = 0;
    for (i, wanted) in chips.iter().copied().chain(std::iter::once(editor_min)).enumerate() {
        let w = wanted.clamp(1, width);
        if x > 0 && x + w > width { row += 1; x = 0; }
        let allocated = if i == chips.len() { width - x } else { w };
        slots.push(Slot { x, row, width: allocated });
        x += allocated + GAP;
    }
    slots
}

fn children(widget: &gtk::Widget) -> Vec<gtk::Widget> {
    let mut result = Vec::new();
    let mut child = widget.first_child();
    while let Some(w) = child {
        child = w.next_sibling();
        if w.should_layout() { result.push(w); }
    }
    result
}

fn widths(children: &[gtk::Widget]) -> (i32, i32, Vec<i32>, i32) {
    let mut minimum = 1;
    let mut natural = 0i32;
    let mut chip_widths = Vec::new();
    let mut editor_min = EDITOR_MIN;
    for (index, child) in children.iter().enumerate() {
        let (min, nat, _, _) = child.measure(gtk::Orientation::Horizontal, -1);
        if index + 1 == children.len() {
            editor_min = min.max(EDITOR_MIN);
            minimum = minimum.max(editor_min);
            natural = natural.saturating_add(editor_min);
        } else {
            minimum = minimum.max(min);
            let w = nat.max(min).max(1);
            chip_widths.push(w);
            natural = natural.saturating_add(w).saturating_add(GAP);
        }
    }
    // Keep the unwrapped width for unconstrained height measurement. The
    // horizontal preferred width is capped separately in WidgetImpl.
    (minimum, natural.max(minimum), chip_widths, editor_min)
}

struct Plan {
    slots: Vec<Slot>,
    heights: Vec<i32>,
    row_heights: Vec<i32>,
    height: i32,
}

fn plan(children: &[gtk::Widget], width: i32) -> Plan {
    if children.is_empty() {
        return Plan { slots: Vec::new(), heights: Vec::new(), row_heights: Vec::new(), height: 0 };
    }
    let (_, _, chip_widths, editor_min) = widths(children);
    let slots = pack(&chip_widths, editor_min, width);
    let mut row_heights = vec![0; slots.last().unwrap().row + 1];
    let heights: Vec<i32> = children.iter().zip(&slots).map(|(child, slot)| {
        let (min, nat, _, _) = child.measure(gtk::Orientation::Vertical, slot.width);
        let h = min.max(nat).max(1);
        row_heights[slot.row] = row_heights[slot.row].max(h);
        h
    }).collect();
    let height = row_heights.iter().sum::<i32>() + ROW_GAP * (row_heights.len() as i32 - 1);
    Plan { slots, heights, row_heights, height }
}

mod imp {
    use super::*;
    #[derive(Default)]
    pub struct InlineRecipients;

    #[glib::object_subclass]
    impl ObjectSubclass for InlineRecipients {
        const NAME: &'static str = "LookoutInlineRecipients";
        type Type = super::InlineRecipients;
        type ParentType = gtk::Widget;
    }

    impl ObjectImpl for InlineRecipients {
        fn dispose(&self) {
            while let Some(child) = self.obj().first_child() { child.unparent(); }
        }
    }

    impl WidgetImpl for InlineRecipients {
        fn request_mode(&self) -> gtk::SizeRequestMode {
            gtk::SizeRequestMode::HeightForWidth
        }

        fn measure(&self, orientation: gtk::Orientation, for_size: i32) -> (i32, i32, i32, i32) {
            let widget = self.obj();
            let children = children(widget.upcast_ref());
            let (min, nat, _, _) = widths(&children);
            if orientation == gtk::Orientation::Horizontal {
                (min, nat.min(NATURAL_CAP).max(min), -1, -1)
            } else {
                // An unconstrained vertical query is the lower height bound
                // used by GtkBoxLayout before it distributes actual width.
                // It must fit a single line, even when preferred horizontal
                // width is capped. Otherwise GtkBox can report min > nat
                // on a wide allocation and reserve an empty second row.
                let width = if for_size < 0 { nat } else { for_size.max(1) };
                let h = plan(&children, width).height;
                (h, h, -1, -1)
            }
        }

        fn size_allocate(&self, width: i32, _height: i32, _baseline: i32) {
            let widget = self.obj();
            let children = children(widget.upcast_ref());
            let plan = plan(&children, width);
            let mut offsets = Vec::with_capacity(plan.row_heights.len());
            let mut y = 0;
            for h in &plan.row_heights { offsets.push(y); y += h + ROW_GAP; }
            let rtl = widget.direction() == gtk::TextDirection::Rtl;
            for ((child, slot), height) in children.iter().zip(&plan.slots).zip(&plan.heights) {
                let x = if rtl { width - slot.x - slot.width } else { slot.x };
                let y = offsets[slot.row] + (plan.row_heights[slot.row] - height) / 2;
                child.size_allocate(&gtk::Allocation::new(x, y, slot.width, *height), -1);
            }
        }

        fn snapshot(&self, snapshot: &gtk::Snapshot) {
            let widget = self.obj();
            for child in children(widget.upcast_ref()) { widget.snapshot_child(&child, snapshot); }
        }
    }
}

glib::wrapper! {
    pub struct InlineRecipients(ObjectSubclass<imp::InlineRecipients>)
        @extends gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget;
}

impl InlineRecipients {
    pub fn new(entry: &gtk::Text) -> Self {
        let widget: Self = glib::Object::new();
        entry.set_parent(&widget);
        widget
    }

    pub fn replace_chips(&self, entry: &gtk::Text, chips: &[gtk::Widget]) {
        let editor = entry.upcast_ref::<gtk::Widget>();
        let mut child = self.first_child();
        while let Some(widget) = child {
            child = widget.next_sibling();
            if &widget != editor { widget.unparent(); }
        }
        for chip in chips { chip.insert_before(self, Some(editor)); }
        self.queue_resize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_editor_fills_line() {
        assert_eq!(pack(&[], 100, 600), vec![Slot { x: 0, row: 0, width: 600 }]);
    }

    #[test]
    fn trailing_editor_uses_remainder() {
        let slots = pack(&[120, 150], 100, 600);
        assert_eq!(slots[2], Slot { x: 276, row: 0, width: 324 });
    }

    #[test]
    fn editor_wraps_only_when_remainder_is_too_small() {
        let exact = pack(&[120, 150], 100, 376);
        assert_eq!(exact[2], Slot { x: 276, row: 0, width: 100 });
        let narrow = pack(&[120, 150], 100, 375);
        assert_eq!(narrow[2], Slot { x: 0, row: 1, width: 375 });
        let wider = pack(&[120, 150], 100, 500);
        assert_eq!(wider[2].row, 0);
    }

    #[test]
    fn unconstrained_height_does_not_reserve_a_wrapped_line() {
        if !crate::gtk_test::gtk_ready() { return; }
        let editor = gtk::Text::builder().hexpand(true).build();
        let surface = InlineRecipients::new(&editor);
        surface.set_hexpand(true);
        let chips: Vec<gtk::Widget> = (0..3).map(|_| {
            gtk::Label::builder().label("Recipient").width_request(260)
                .height_request(30).build().upcast()
        }).collect();
        surface.replace_chips(&editor, &chips);
        let (min_width, natural_width, _, _) = surface.measure(gtk::Orientation::Horizontal, -1);
        assert!(natural_width <= NATURAL_CAP.max(min_width));
        let (base_min, base_nat, _, _) = surface.measure(gtk::Orientation::Vertical, -1);
        let (wide_min, wide_nat, _, _) = surface.measure(gtk::Orientation::Vertical, 1150);
        assert_eq!((base_min, base_nat), (wide_min, wide_nat));
        assert!(surface.measure(gtk::Orientation::Vertical, 500).0 > wide_min);

        // Reproduce the actual composer hierarchy: a fixed label/button
        // beside the expanding surface. A wide parent must not reserve the
        // height of the layout at the capped preferred width.
        let header = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        header.append(&gtk::Button::builder().label("To…").width_request(56).build());
        header.append(&surface);
        let (min, nat, _, _) = header.measure(gtk::Orientation::Vertical, 1228);
        assert_eq!(min, nat);
        assert!(min < 2 * wide_min + ROW_GAP);
    }

    #[test]
    fn multiple_wrapped_chips_and_tiny_width() {
        let slots = pack(&[200, 200, 200], 100, 450);
        assert_eq!(slots[3], Slot { x: 203, row: 1, width: 247 });
        assert_eq!(pack(&[200], 100, 40)[1], Slot { x: 0, row: 1, width: 40 });
    }
}
