//! The single-line message list's column header (OUTLOOK_PARITY.md M-07 /
//! UX-27).
//!
//! One flat button per column, in the configured order, with a caret on the
//! column the list is sorted by. Clicking a column sorts by it (Outlook's
//! natural direction first - newest, largest, high importance, flagged, with
//! attachments; A-Z for text - and the opposite direction on a second click).
//! Right-clicking opens Sort ascending / Sort descending, a check list of
//! columns, and Reset columns. The chosen set is stored in
//! `mail-list-columns`.
//!
//! The header is only visible in the single-line list style (the three-line
//! row has no columns to name). The widths here are the same constants the
//! rows use, so the labels sit exactly over their cells; both sides are bare
//! boxes rather than a `GtkColumnView`, because section headers have to span
//! the full width and a column view cannot do that.
//!
//! Copyright (C) <2026>  <Gavin Graham & Contributors>
//! Software released under the GPL3 license

use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};

use gtk::glib;
use gtk::prelude::*;

use crate::context_menu::{ActionSpec, ContextMenu, Dispatch, MenuDescription};
use crate::message_columns::{self, MessageColumn, ROW_LEADING_WIDTH};
use crate::message_list::SortKey;
use crate::settings::SettingsStore;

/// A single model for header and row widths. Subject takes the remaining
/// space; dragging either of its boundaries changes an adjacent fixed column.
/// A narrow pane can temporarily compress preferences without overwriting them.
type ColumnWidths = Vec<(MessageColumn, i32)>;

fn minimum_width(column: MessageColumn) -> i32 {
    match column {
        MessageColumn::Importance => 24,
        MessageColumn::Attachment => 28,
        MessageColumn::From | MessageColumn::To => 60,
        MessageColumn::Subject => message_columns::SUBJECT_MIN_WIDTH,
        MessageColumn::Received => 56,
        MessageColumn::Size => 48,
    }
}

fn lookup_width(widths: &ColumnWidths, column: MessageColumn) -> i32 {
    widths.iter().find(|(c, _)| *c == column).map(|(_, w)| *w)
        .unwrap_or_else(|| if column.expands() { minimum_width(column) } else { column.width() })
}

fn set_preferred(widths: &mut ColumnWidths, column: MessageColumn, width: i32) {
    if column.expands() { return; }
    let width = width.clamp(minimum_width(column), 4096);
    if let Some((_, current)) = widths.iter_mut().find(|(c, _)| *c == column) {
        *current = width;
    } else {
        widths.push((column, width));
    }
}

fn parse_widths(values: &[String]) -> ColumnWidths {
    let mut widths = Vec::new();
    for value in values {
        let Some((id, width)) = value.split_once('=') else { continue; };
        let (Some(column), Ok(width)) = (MessageColumn::from_id(id), width.parse::<i32>()) else { continue; };
        if width > 0 { set_preferred(&mut widths, column, width); }
    }
    widths
}

fn fitted_widths(visible: &[MessageColumn], preferred: &ColumnWidths, pane_width: i32) -> ColumnWidths {
    let mut widths: ColumnWidths = visible.iter().map(|&column| {
        let width = if column.expands() { minimum_width(column) } else { lookup_width(preferred, column) };
        (column, width)
    }).collect();
    let overhead = message_columns::ROW_LEADING_WIDTH + message_columns::ROW_TRAILING_MARGIN
        + message_columns::COLUMN_SPACING * visible.len().saturating_sub(1) as i32;
    if pane_width <= 0 { return widths; }
    let mut excess = (overhead + widths.iter().map(|(_, w)| *w).sum::<i32>() - pane_width).max(0);
    for column in [MessageColumn::Size, MessageColumn::Received, MessageColumn::To, MessageColumn::From,
        MessageColumn::Attachment, MessageColumn::Importance] {
        if let Some((_, width)) = widths.iter_mut().find(|(c, _)| *c == column) {
            let shrink = excess.min((*width - minimum_width(column)).max(0));
            *width -= shrink;
            excess -= shrink;
        }
    }
    let slack = (pane_width - overhead - widths.iter().map(|(_, w)| *w).sum::<i32>()).max(0);
    if let Some((_, width)) = widths.iter_mut().find(|(c, _)| c.expands()) {
        *width += slack;
    }
    widths
}

fn boundary_sizes(left: MessageColumn, right: MessageColumn, start: (i32, i32), delta: i32) -> (i32, i32) {
    let low = minimum_width(left) - start.0;
    let high = start.1 - minimum_width(right);
    if low > high { return start; }
    let delta = delta.clamp(low, high);
    (start.0 + delta, start.1 - delta)
}

/// The list's column configuration, shared by the header and every row.
///
/// `configured` is what the user chose (Outlook's default until they change
/// it); `visible` is that set fitted to the list's current width. Rows read
/// `visible` at bind time, so a width or configuration change rebuilds the
/// header and refreshes the list.
#[derive(Clone)]
pub(crate) struct ColumnState {
    configured: Rc<RefCell<Vec<MessageColumn>>>,
    sent_configured: Rc<RefCell<Vec<MessageColumn>>>,
    sent_view: Rc<Cell<bool>>,
    visible: Rc<RefCell<Vec<MessageColumn>>>,
    /// The width last fitted against, so a configuration change can re-fit
    /// without waiting for a resize.
    width: Rc<Cell<i32>>,
    preferred: Rc<RefCell<ColumnWidths>>,
    effective: Rc<RefCell<ColumnWidths>>,
    // Weak handles to recycled row cells; resizing updates them in place.
    row_cells: Rc<RefCell<Vec<(MessageColumn, glib::WeakRef<gtk::Widget>)>>>,
}

impl ColumnState {
    pub(crate) fn from_settings(settings: &SettingsStore) -> Self {
        let configured = message_columns::parse_columns(&settings.get_strv(crate::settings::MAIL_LIST_COLUMNS));
        let sent_ids = settings.get_strv(crate::settings::MAIL_SENT_LIST_COLUMNS);
        let sent_configured = if sent_ids.iter().any(|id| MessageColumn::from_id(id).is_some()) {
            message_columns::parse_columns(&sent_ids)
        } else {
            message_columns::DEFAULT_SENT_COLUMNS.to_vec()
        };
        let preferred = parse_widths(&settings.get_strv(crate::settings::MAIL_LIST_COLUMN_WIDTHS));
        let effective = fitted_widths(&configured, &preferred, 0);
        ColumnState {
            visible: Rc::new(RefCell::new(configured.clone())),
            configured: Rc::new(RefCell::new(configured)),
            sent_configured: Rc::new(RefCell::new(sent_configured)),
            sent_view: Rc::new(Cell::new(false)),
            width: Rc::new(Cell::new(0)),
            preferred: Rc::new(RefCell::new(preferred)),
            effective: Rc::new(RefCell::new(effective)),
            row_cells: Rc::new(RefCell::new(Vec::new())),
        }
    }

    pub(crate) fn sent_view(&self) -> bool { self.sent_view.get() }

    fn configured(&self) -> &RefCell<Vec<MessageColumn>> {
        if self.sent_view() { &self.sent_configured } else { &self.configured }
    }

    fn settings_key(&self) -> &'static str {
        if self.sent_view() { crate::settings::MAIL_SENT_LIST_COLUMNS }
        else { crate::settings::MAIL_LIST_COLUMNS }
    }

    fn default_columns(&self) -> &'static [MessageColumn] {
        if self.sent_view() { &message_columns::DEFAULT_SENT_COLUMNS }
        else { &message_columns::DEFAULT_COLUMNS }
    }

    fn set_sent_view(&self, sent: bool) -> bool {
        if self.sent_view.replace(sent) == sent { return false; }
        self.refit();
        true
    }

    pub(crate) fn visible(&self) -> Vec<MessageColumn> {
        self.visible.borrow().clone()
    }

    pub(crate) fn is_visible(&self, column: MessageColumn) -> bool {
        self.visible.borrow().contains(&column)
    }

    /// Whether the user has the column chosen, regardless of whether the
    /// current width can fit it. The column chooser's checks follow this, so a
    /// column that is merely shed for space still reads as on.
    pub(crate) fn is_configured(&self, column: MessageColumn) -> bool {
        self.configured().borrow().contains(&column)
    }

    /// Fits the configured columns to `width`, returning whether the visible
    /// set changed. Called on every list-width notification; only a change in
    /// the band the columns fit into does any work.
    pub(crate) fn fit_width(&self, width: i32) -> bool {
        self.width.set(width);
        self.refit()
    }

    /// Adds or removes one column, persists the new order, and re-fits to the
    /// current width. Returns whether the visible set changed.
    pub(crate) fn set_column_visible(&self, column: MessageColumn, visible: bool, settings: &SettingsStore) -> bool {
        let mut configured = self.configured().borrow_mut();
        let was_present = configured.contains(&column);
        if visible && !was_present {
            configured.push(column);
        } else if !visible && was_present {
            configured.retain(|candidate| *candidate != column);
        } else {
            return false;
        }
        // Keep the chooser's order stable: MessageColumn::ALL is the display
        // order, and Outlook's default is that order minus To.
        let all = MessageColumn::ALL;
        configured.sort_by_key(|candidate| all.iter().position(|value| value == candidate).unwrap_or(usize::MAX));
        let ids = message_columns::columns_to_ids(&configured);
        drop(configured);
        settings.set_strv(self.settings_key(), ids);
        self.refit()
    }

    /// Restores the active profile's default columns and shared widths.
    pub(crate) fn reset(&self, settings: &SettingsStore) -> bool {
        let mut configured = self.configured().borrow_mut();
        *configured = self.default_columns().to_vec();
        let ids = message_columns::columns_to_ids(&configured);
        drop(configured);
        settings.set_strv(self.settings_key(), ids);
        let widths_changed = !self.preferred.borrow().is_empty();
        self.preferred.borrow_mut().clear();
        self.save_widths(settings);
        self.refit() || widths_changed
    }

    fn refit(&self) -> bool {
        let fitted = if self.width.get() <= 0 { self.configured().borrow().clone() }
            else { message_columns::columns_for_width(&self.configured().borrow(), self.width.get()) };
        let changed = {
            let mut visible = self.visible.borrow_mut();
            if *visible == fitted { false } else { *visible = fitted; true }
        };
        self.update_effective(changed);
        changed
    }

    fn update_effective(&self, visible_changed: bool) {
        let fitted = fitted_widths(&self.visible.borrow(), &self.preferred.borrow(), self.width.get());
        let changed = {
            let mut effective = self.effective.borrow_mut();
            if *effective == fitted { false } else { *effective = fitted; true }
        };
        if changed || visible_changed { self.apply_registered_cells(); }
    }

    fn effective_width(&self, column: MessageColumn) -> i32 {
        lookup_width(&self.effective.borrow(), column)
    }

    fn cell_width(&self, column: MessageColumn) -> i32 {
        if column.expands() { minimum_width(column) } else { self.effective_width(column) }
    }

    fn resize_boundary(&self, left: MessageColumn, right: MessageColumn, start: (i32, i32), delta: i32) {
        let (left_width, right_width) = boundary_sizes(left, right, start, delta);
        {
            let mut preferred = self.preferred.borrow_mut();
            set_preferred(&mut preferred, left, left_width);
            set_preferred(&mut preferred, right, right_width);
        }
        self.update_effective(false);
    }

    fn save_widths(&self, settings: &SettingsStore) {
        let values = self.preferred.borrow().iter().map(|(column, width)| format!("{}={width}", column.id())).collect();
        settings.set_strv(crate::settings::MAIL_LIST_COLUMN_WIDTHS, values);
    }

    pub(crate) fn register_cells(&self, cells: &[(MessageColumn, gtk::Widget)]) {
        {
            let mut registered = self.row_cells.borrow_mut();
            registered.retain(|(_, weak)| weak.upgrade().is_some());
            registered.extend(cells.iter().map(|(column, cell)| (*column, cell.downgrade())));
        }
        apply_cell_visibility(cells, self);
    }

    fn apply_registered_cells(&self) {
        let cells: Vec<_> = {
            let mut registered = self.row_cells.borrow_mut();
            registered.retain(|(_, weak)| weak.upgrade().is_some());
            registered.iter().filter_map(|(column, weak)| weak.upgrade().map(|cell| (*column, cell))).collect()
        };
        // No RefCell guard is held while GTK may emit a synchronous signal.
        apply_cell_visibility(&cells, self);
    }
}

/// The widget pieces of the header, cloned into the button and menu handlers.
struct HeaderParts {
    cells: gtk::Box,
    buttons: Rc<RefCell<Vec<ColumnButton>>>,
    state: ColumnState,
    settings: Rc<SettingsStore>,
    sort: Rc<Cell<(SortKey, bool)>>,
    set_sort: Rc<dyn Fn(SortKey, bool, bool)>,
    on_columns_changed: Rc<dyn Fn()>,
}

struct ColumnButton {
    column: MessageColumn,
    button: gtk::Button,
    caret: gtk::Image,
}

/// Builds the header. The returned `Rc` must be kept alive for as long as the
/// window is open (the list-style controller holds it). Every handler below
/// captures a `Weak` back to it, so the widget tree and the header cannot
/// leak each other.
pub(crate) fn build_column_header(
    state: ColumnState,
    settings: Rc<SettingsStore>,
    set_sort: Rc<dyn Fn(SortKey, bool, bool)>,
    on_columns_changed: Rc<dyn Fn()>,
) -> Rc<ColumnHeader> {
    let root_build = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(0)
        .css_classes(["message-column-header"])
        .build();
    // The header's fixed column widths must not become the message pane's
    // minimum: the scrollbar-less viewport clips instead of propagating them,
    // so Automatic can shrink the pane below the columns and fall back to the
    // three-line rows. The inner box stays visible; the viewport is toggled.
    let viewport = gtk::ScrolledWindow::builder()
        .child(&root_build)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::Never)
        .propagate_natural_width(false)
        .propagate_natural_height(true)
        .has_frame(false)
        .hexpand(true)
        .visible(false)
        .build();
    viewport.add_css_class("message-column-header-viewport");
    Rc::new(ColumnHeader {
        parts: HeaderParts {
            cells: gtk::Box::builder()
                .orientation(gtk::Orientation::Horizontal)
                .spacing(crate::message_columns::COLUMN_SPACING)
                .hexpand(true)
                .margin_end(crate::message_columns::ROW_TRAILING_MARGIN)
                .build(),
            buttons: Rc::new(RefCell::new(Vec::new())),
            state,
            settings,
            sort: Rc::new(Cell::new((SortKey::Date, true))),
            set_sort,
            on_columns_changed,
        },
        root_build,
        viewport,
    })
}

/// The header row widget.
pub(crate) struct ColumnHeader {
    parts: HeaderParts,
    root_build: gtk::Box,
    viewport: gtk::ScrolledWindow,
}

impl ColumnHeader {
    pub(crate) fn root(&self) -> gtk::ScrolledWindow {
        self.viewport.clone()
    }

    /// Whether the header is on screen.
    pub(crate) fn set_visible(&self, visible: bool) {
        self.viewport.set_visible(visible);
    }

    /// Builds the column buttons once the root is in the widget tree. Called
    /// by `window.rs` after construction (and again after a column change).
    pub(crate) fn init(self: &Rc<Self>) {
        let root = &self.root_build;
        let gutter = gtk::Box::builder().width_request(ROW_LEADING_WIDTH).build();
        root.append(&gutter);
        root.append(&self.parts.cells);
        self.rebuild();
    }

    /// Replaces the buttons with the current visible columns, restoring the
    /// caret from the remembered sort.
    pub(crate) fn rebuild(self: &Rc<Self>) {
        let cells = &self.parts.cells;
        while let Some(child) = cells.first_child() {
            cells.remove(&child);
        }
        self.parts.buttons.borrow_mut().clear();

        let visible = self.parts.state.visible();
        for (index, &column) in visible.iter().enumerate() {
            let caret = gtk::Image::builder().icon_name("pan-down-symbolic").pixel_size(6).visible(false).build();
            let content = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(3).hexpand(true).build();
            // The icon-only columns (importance, attachment) use the same
            // glyphs as the rows; a word would not fit their width.
            let icon_name = match column {
                MessageColumn::Importance => Some("emblem-important-symbolic"),
                MessageColumn::Attachment => Some("mail-attachment-symbolic"),
                _ => None,
            };
            if let Some(icon_name) = icon_name {
                let icon = gtk::Image::builder().icon_name(icon_name).pixel_size(12).build();
                content.append(&icon);
            } else {
                // Cap the label's natural width to its cell, so a button with
                // a long word cannot widen the column and shift the ones after
                // it away from the row cells.
                let label = gtk::Label::builder()
                    .label(column.label())
                    .ellipsize(gtk::pango::EllipsizeMode::End)
                    .width_chars(0)
                    .max_width_chars(0)
                    .hexpand(true)
                    .build();
                if matches!(column, MessageColumn::Received | MessageColumn::Size) {
                    label.set_xalign(1.0);
                } else {
                    label.set_xalign(0.0);
                }
                content.append(&label);
            }
            content.append(&caret);
            let button = gtk::Button::builder()
                .child(&content)
                .css_classes(["flat", "message-column-header-button"])
                .tooltip_text(format!("Sort by {}", column.label()))
                .hexpand(column.expands())
                .halign(gtk::Align::Fill)
                .width_request(self.parts.state.cell_width(column))
                .focusable(true)
                .build();
            button.update_property(&[gtk::accessible::Property::Label(column.label())]);

            {
                let weak = Rc::downgrade(self);
                button.connect_clicked(move |_| {
                    if let Some(header) = weak.upgrade() {
                        header.click_column(column);
                    }
                });
            }
            {
                let weak = Rc::downgrade(self);
                let button_for_menu = button.clone();
                let gesture = gtk::GestureClick::new();
                gesture.set_button(gtk::gdk::BUTTON_SECONDARY);
                gesture.connect_pressed(move |gesture, _, x, y| {
                    gesture.set_state(gtk::EventSequenceState::Claimed);
                    if let Some(header) = weak.upgrade() {
                        header.open_menu(&button_for_menu, column, x, y);
                    }
                });
                button.add_controller(gesture);
            }

            // The handle is an overlay, not another column: it does not
            // alter the cell's measured width or the header/row alignment.
            let wrapper = gtk::Overlay::builder().child(&button).hexpand(column.expands()).build();
            if let Some(&next) = visible.get(index + 1) {
                let handle = gtk::Box::builder().width_request(8)
                    .halign(gtk::Align::End).valign(gtk::Align::Fill)
                    .css_classes(["message-column-resize-handle"])
                    .tooltip_text("Drag to resize columns").build();
                handle.set_cursor_from_name(Some("col-resize"));
                wrapper.add_overlay(&handle);
                wrapper.set_measure_overlay(&handle, false);
                let drag = gtk::GestureDrag::new();
                drag.set_button(gtk::gdk::BUTTON_PRIMARY);
                let start = Rc::new(Cell::new(None::<(i32, i32)>));
                {
                    let weak = Rc::downgrade(self);
                    let start = start.clone();
                    drag.connect_drag_begin(move |gesture, _, _| {
                        let Some(header) = weak.upgrade() else { return; };
                        start.set(Some((header.parts.state.effective_width(column), header.parts.state.effective_width(next))));
                        gesture.set_state(gtk::EventSequenceState::Claimed);
                    });
                }
                {
                    let weak = Rc::downgrade(self);
                    let start = start.clone();
                    drag.connect_drag_update(move |_, dx, _| {
                        let (Some(header), Some(initial)) = (weak.upgrade(), start.get()) else { return; };
                        header.parts.state.resize_boundary(column, next, initial, dx.round() as i32);
                        header.update_button_widths();
                    });
                }
                {
                    let weak = Rc::downgrade(self);
                    drag.connect_drag_end(move |_, _, _| {
                        start.set(None);
                        if let Some(header) = weak.upgrade() {
                            header.parts.state.save_widths(&header.parts.settings);
                        }
                    });
                }
                handle.add_controller(drag);
            }
            cells.append(&wrapper);
            self.parts.buttons.borrow_mut().push(ColumnButton { column, button, caret });
        }
        self.refresh(self.parts.sort.get().0, self.parts.sort.get().1);
    }

    /// Updates the carets to show `key` in `descending` order.
    pub(crate) fn refresh(&self, key: SortKey, descending: bool) {
        self.parts.sort.set((key, descending));
        for entry in self.parts.buttons.borrow().iter() {
            let active = entry.column.sort_key() == key;
            entry.caret.set_visible(active);
            if active {
                entry.caret.set_icon_name(Some(if descending { "pan-down-symbolic" } else { "pan-up-symbolic" }));
                entry.button.set_tooltip_text(Some(&format!(
                    "Sorted by {} ({}); click to reverse",
                    entry.column.label(),
                    if descending {
                        entry.column.sort_key().descending_label()
                    } else {
                        entry.column.sort_key().ascending_label()
                    }
                )));
            } else {
                entry.button.set_tooltip_text(Some(&format!("Sort by {}", entry.column.label())));
            }
        }
    }

    fn update_button_widths(&self) {
        let buttons: Vec<_> = self.parts.buttons.borrow().iter().map(|entry| (entry.column, entry.button.clone())).collect();
        for (column, button) in buttons {
            let width = self.parts.state.cell_width(column);
            if button.width_request() != width { button.set_width_request(width); }
        }
    }

    /// Re-fit on pane resize. Only a change of visible columns rebuilds the
    /// header; width-only changes update the same live widgets.
    pub(crate) fn set_width(self: &Rc<Self>, width: i32) {
        if self.parts.state.fit_width(width) {
            self.rebuild();
            (self.parts.on_columns_changed)();
        } else {
            self.update_button_widths();
        }
    }

    pub(crate) fn set_sent_view(self: &Rc<Self>, sent: bool) {
        if self.parts.state.set_sent_view(sent) {
            self.rebuild();
            (self.parts.on_columns_changed)();
        }
    }

    fn click_column(&self, column: MessageColumn) {
        let (current, descending) = self.parts.sort.get();
        let key = column.sort_key();
        let descending = if current == key { !descending } else { key.natural_descending() };
        (self.parts.set_sort)(key, descending, true);
    }

    fn set_column_visible(self: &Rc<Self>, column: MessageColumn, visible: bool) {
        if self.parts.state.set_column_visible(column, visible, &self.parts.settings) {
            self.rebuild();
            (self.parts.on_columns_changed)();
        }
    }

    fn reset_columns(self: &Rc<Self>) {
        if self.parts.state.reset(&self.parts.settings) {
            self.rebuild();
            (self.parts.on_columns_changed)();
        }
    }

    /// The header's right-click menu: sort this column either way, choose the
    /// columns, reset. Built fresh per opening (the message-menu idiom), so
    /// the check marks and the popover's lifetime stay simple.
    fn open_menu(self: &Rc<Self>, anchor: &gtk::Button, column: MessageColumn, x: f64, y: f64) {
        let mut columns = MenuDescription::new().section();
        for candidate in MessageColumn::ALL {
            columns = columns.custom(format!("col-{}", candidate.id()));
        }
        let description = MenuDescription::new()
            .section()
            .action("Sort ascending", "cols.ascending")
            .action("Sort descending", "cols.descending")
            .submenu("Columns", columns)
            .section()
            .action("Reset columns", "cols.reset");

        let weak = Rc::downgrade(self);
        let target = column;
        let dispatch: Dispatch = Rc::new(move |name, _| {
            let Some(header) = weak.upgrade() else { return };
            match name {
                "ascending" => (header.parts.set_sort)(target.sort_key(), false, true),
                "descending" => (header.parts.set_sort)(target.sort_key(), true, true),
                "reset" => header.reset_columns(),
                _ => {}
            }
        });
        let specs = [ActionSpec::simple("ascending"), ActionSpec::simple("descending"), ActionSpec::simple("reset")];
        let menu = ContextMenu::new(&description, &specs, dispatch);
        for candidate in MessageColumn::ALL {
            let check = gtk::CheckButton::with_label(candidate.label());
            check.set_active(self.parts.state.is_configured(candidate));
            {
                let weak = Rc::downgrade(self);
                check.connect_toggled(move |check| {
                    if let Some(header) = weak.upgrade() {
                        header.set_column_visible(candidate, check.is_active());
                    }
                });
            }
            menu.add_child(&check, &format!("col-{}", candidate.id()));
        }

        let popover = menu.popover.clone();
        popover.set_has_arrow(false);
        popover.set_halign(gtk::Align::Start);
        // Parented to the header root, not the clicked button: toggling a
        // column rebuilds the buttons, and a popover whose parent is destroyed
        // would close mid-choice.
        popover.set_parent(&self.root_build);
        // The group lives on the popover, not the header, so reopening the
        // menu never stacks another "cols" group on the same widget.
        popover.insert_action_group("cols", Some(&menu.actions));
        let (x, y) = anchor
            .compute_point(&self.root_build, &gtk::graphene::Point::new(x as f32, y as f32))
            .map(|point| (point.x() as f64, point.y() as f64))
            .unwrap_or((x, y));
        popover.set_pointing_to(Some(&gtk::gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
        popover.connect_closed(|popover| {
            let popover = popover.clone();
            glib::idle_add_local_once(move || popover.unparent());
        });
        popover.popup();
    }
}

/// A row/header cell box for `column`: the fixed width, the expanding subject,
/// and centred content. The row fills it with the column's widgets.
pub(crate) fn column_cell(column: MessageColumn) -> gtk::Box {
    let cell = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(3)
        .valign(gtk::Align::Center)
        .hexpand(column.expands())
        .build();
    cell.add_css_class("message-single-cell");
    cell.set_width_request(if column.expands() { minimum_width(column) } else { column.width() });
    cell
}

/// Applies the state's visible set to one row's cells (message or thread).
pub(crate) fn apply_cell_visibility(cells: &[(MessageColumn, gtk::Widget)], state: &ColumnState) {
    for (column, cell) in cells {
        let width = state.cell_width(*column);
        if cell.width_request() != width { cell.set_width_request(width); }
        cell.set_visible(state.is_visible(*column));
    }
}

/// The sort path's caret refresh. A free function so `window.rs` can call it
/// with the weak header it already holds.
pub(crate) fn refresh_header(header: &Weak<ColumnHeader>, key: SortKey, descending: bool) {
    if let Some(header) = header.upgrade() {
        header.refresh(key, descending);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message_columns::DEFAULT_COLUMNS;

    fn state() -> ColumnState {
        ColumnState {
            configured: Rc::new(RefCell::new(DEFAULT_COLUMNS.to_vec())),
            sent_configured: Rc::new(RefCell::new(message_columns::DEFAULT_SENT_COLUMNS.to_vec())),
            sent_view: Rc::new(Cell::new(false)),
            visible: Rc::new(RefCell::new(DEFAULT_COLUMNS.to_vec())),
            width: Rc::new(Cell::new(0)),
            preferred: Rc::new(RefCell::new(Vec::new())),
            effective: Rc::new(RefCell::new(fitted_widths(&DEFAULT_COLUMNS, &Vec::new(), 0))),
            row_cells: Rc::new(RefCell::new(Vec::new())),
        }
    }

    #[test]
    fn drag_boundary_preserves_total_and_saved_widths_survive_narrowing() {
        let state = state();
        state.fit_width(1200);
        let from = MessageColumn::From;
        let subject = MessageColumn::Subject;
        let start = (state.effective_width(from), state.effective_width(subject));
        state.resize_boundary(from, subject, start, 100);
        assert_eq!(state.effective_width(from), start.0 + 100);
        assert_eq!(state.effective_width(subject), start.1 - 100);
        state.fit_width(500);
        assert!(state.effective_width(from) < start.0 + 100);
        state.fit_width(1200);
        assert_eq!(state.effective_width(from), start.0 + 100);
        assert_eq!(boundary_sizes(from, subject, (170, 100), 999), (180, 90));
        assert_eq!(lookup_width(&parse_widths(&["from=240".into(), "unknown=80".into(), "size=-1".into()]), from), 240);
    }

    fn ids(state: &ColumnState) -> Vec<&'static str> {
        state.visible().iter().map(|column| column.id()).collect()
    }

    #[test]
    fn sent_profile_has_to_and_restores_inbox_columns() {
        let state = state();
        state.fit_width(1200);
        assert!(state.set_sent_view(true));
        assert!(state.visible().contains(&MessageColumn::To));
        assert!(!state.visible().contains(&MessageColumn::From));
        state.fit_width(400);
        assert!(state.visible().contains(&MessageColumn::To));
        assert!(state.set_sent_view(false));
        assert!(state.visible().contains(&MessageColumn::From));
        assert!(!state.visible().contains(&MessageColumn::To));
    }

    #[test]
    fn the_visible_set_narrows_and_widens_with_the_pane() {
        let state = state();
        // The default set already fits a wide pane, so the first fit there is
        // a no-op; the fits that matter are the narrowing ones.
        assert!(!state.fit_width(1200));
        assert!(ids(&state).contains(&"size"));
        assert!(!state.fit_width(1200), "a width inside the same band is a no-op");

        assert!(state.fit_width(500));
        let narrow = ids(&state);
        assert!(narrow.contains(&"from"));
        assert!(narrow.contains(&"subject"));
        assert!(narrow.contains(&"received"));
        assert!(!narrow.contains(&"size"), "size is shed before the core");

        assert!(state.fit_width(1200));
        assert!(ids(&state).contains(&"size"), "growing the pane brings the column back");
    }
}
