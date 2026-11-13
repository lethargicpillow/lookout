//! Virtualized People GAL. The model contains data objects, not a widget for
//! every directory entry; GTK creates and recycles only its visible rows.
use std::{cell::{Cell, RefCell}, rc::Rc};
use gtk::{gio, glib, prelude::*};
use lookout_graph::DirectoryPerson;
use crate::{contacts_view::{directory_person_display_name, directory_person_secondary}, window::UiState};

pub(crate) struct DirectoryList {
    pub root: gtk::Stack,
    store: gio::ListStore,
    selection: gtk::SingleSelection,
    message: gtk::Label,
    updating: Rc<Cell<bool>>,
    rendered: Cell<Option<(u64, usize, bool)>>,
}

impl DirectoryList {
    pub(crate) fn new(stored: &gtk::ScrolledWindow, state: &Rc<RefCell<UiState>>) -> Self {
        let store = gio::ListStore::new::<glib::BoxedAnyObject>();
        let selection = gtk::SingleSelection::new(Some(store.clone()));
        selection.set_autoselect(false);
        selection.set_can_unselect(true);
        let factory = gtk::SignalListItemFactory::new();
        factory.connect_setup(|_, item| {
            let Some(item) = item.downcast_ref::<gtk::ListItem>() else { return };
            let avatar = gtk::Label::builder().css_classes(["avatar-circle"]).width_request(32).height_request(32)
                .valign(gtk::Align::Center).build();
            let name = gtk::Label::builder().xalign(0.0).ellipsize(gtk::pango::EllipsizeMode::End).build();
            let detail = gtk::Label::builder().xalign(0.0).ellipsize(gtk::pango::EllipsizeMode::End)
                .css_classes(["dim-label", "caption"]).build();
            for label in [&avatar, &name, &detail] { crate::privacy::mark(label); }
            let text = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(2)
                .hexpand(true).valign(gtk::Align::Center).build();
            text.append(&name);
            text.append(&detail);
            let row = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(8)
                .margin_start(10).margin_end(10).margin_top(6).margin_bottom(6).build();
            row.append(&avatar);
            row.append(&text);
            item.set_child(Some(&row));
        });
        factory.connect_bind(|_, item| {
            let Some(item) = item.downcast_ref::<gtk::ListItem>() else { return };
            let Some(object) = item.item().and_downcast::<glib::BoxedAnyObject>() else { return };
            let person = object.borrow::<DirectoryPerson>();
            let Some(row) = item.child().and_downcast::<gtk::Box>() else { return };
            let Some(avatar) = row.first_child().and_downcast::<gtk::Label>() else { return };
            let Some(text) = row.last_child().and_downcast::<gtk::Box>() else { return };
            let Some(name) = text.first_child().and_downcast::<gtk::Label>() else { return };
            let Some(detail) = text.last_child().and_downcast::<gtk::Label>() else { return };
            let display = directory_person_display_name(&person);
            name.set_label(&display);
            detail.set_label(&directory_person_secondary(&person));
            avatar.set_label(&crate::message_header::initials(Some(&display), &person.address));
            // Recycled rows must not retain the preceding person's colour.
            avatar.set_css_classes(&["avatar-circle"]);
            avatar.add_css_class(crate::message_header::avatar_color_class(&person.address));
            crate::privacy::mark(&avatar);
        });
        let list = gtk::ListView::new(Some(selection.clone()), Some(factory));
        list.set_single_click_activate(false);
        let scroller = gtk::ScrolledWindow::builder().child(&list).vexpand(true)
            .hscrollbar_policy(gtk::PolicyType::Never).build();
        let message = gtk::Label::builder().wrap(true).xalign(0.0).halign(gtk::Align::Fill)
            .valign(gtk::Align::Start).margin_start(10).margin_end(10).margin_top(10)
            .css_classes(["dim-label"]).build();
        crate::privacy::mark_ui(&message);
        let root = gtk::Stack::builder().vexpand(true).hexpand(true).hhomogeneous(false).vhomogeneous(false).build();
        root.add_named(stored, Some("stored"));
        root.add_named(&scroller, Some("directory"));
        root.add_named(&message, Some("message"));
        root.set_visible_child_name("stored");

        let updating = Rc::new(Cell::new(false));
        let weak = Rc::downgrade(state);
        let guard = updating.clone();
        selection.connect_selected_notify(move |sel| {
            if guard.get() { return; }
            let Some(state) = weak.upgrade() else { return };
            let refresh = {
                let mut st = state.borrow_mut();
                if !st.contacts_directory_active || !st.contacts_directory_local { return; }
                let index = sel.selected() as usize;
                st.contacts_directory_selected = (index < st.contacts_directory_results.len()).then_some(index);
                st.contacts_details_refresh.clone()
            };
            if let Some(refresh) = refresh { refresh(); }
        });
        Self { root, store, selection, message, updating, rendered: Cell::new(None) }
    }

    pub(crate) fn show_stored(&self) {
        self.root.set_visible_child_name("stored");
    }

    pub(crate) fn render(&self, state: &Rc<RefCell<UiState>>) {
        let (key, selected, query) = {
            let st = state.borrow();
            ((st.contacts_directory_generation, st.contacts_directory_results.len(), st.contacts_directory_searching),
             st.contacts_directory_selected, st.contacts_directory_query.clone())
        };
        self.updating.set(true);
        if self.rendered.get() != Some(key) {
            let objects: Vec<_> = state.borrow().contacts_directory_results.iter()
                .cloned().map(glib::BoxedAnyObject::new).collect();
            self.store.splice(0, self.store.n_items(), &objects);
            self.rendered.set(Some(key));
        }
        self.selection.set_selected(selected.map(|i| i as u32).unwrap_or(gtk::INVALID_LIST_POSITION));
        self.updating.set(false);
        if key.2 {
            self.message.set_label("Searching the directory…");
            self.root.set_visible_child_name("message");
        } else if key.1 == 0 {
            self.message.set_label(&if query.is_empty() { "No directory entries available".into() }
                else { format!("No matches in the directory for “{query}”") });
            self.root.set_visible_child_name("message");
        } else {
            self.root.set_visible_child_name("directory");
        }
    }
}
