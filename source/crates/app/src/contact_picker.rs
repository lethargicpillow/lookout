//! The compose window's "To" button: a modal picker over every known
//! contact (CardDAV address books across every connected account) and every
//! contact list, with checkbox multi-select and an "Add" button that hands
//! the picks back to the caller. Modeled on
//! `identities.rs::show_manage_dialog`'s dialog skeleton and the People
//! screen's own checkbox-row pattern (`contacts_view.rs`), stripped down to
//! just search-and-pick.

/// Copyright (C) <2026>  <Gavin Graham & Contributors>
/// Software released under the GPL3 license
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use adw::prelude::*;
use gtk::{gio, glib};
use lookout_core::{ContactList, EmailAddress};
use lookout_graph::DirectoryPerson;

use crate::contacts_view::dedupe_addresses;
use crate::directory::DirectoryLookup;
use crate::recipient_entry::Suggestion;
use crate::window::UiState;

/// Opens the picker over the given anchor widget's window, handing whatever
/// the user checked to the given callback. Threaded into `build_compose_view`
/// so the To button can open it without the composer needing to know about
/// `UiState` itself.
pub type ContactPickerOpener = Rc<dyn Fn(gtk::Widget, Rc<dyn Fn(Vec<Suggestion>)>)>;

/// One pickable row: a stored address, a contact list, or a read-only
/// directory/GAL hit (item 4.7.7). A directory row carries no stored contact
/// behind it, so it can only be picked - never edited - and picking one adds
/// its address as a normal recipient.
#[derive(Clone)]
enum Item {
    Address(EmailAddress),
    List(ContactList),
    Directory(DirectoryPerson),
}

impl Item {
    fn label(&self) -> String {
        match self {
            Item::Address(address) => address.display_label().to_string(),
            Item::List(list) => list.name.clone(),
            Item::Directory(person) => directory_name(person),
        }
    }

    /// The stable selection key: a lowercased address, `list:<lowercased
    /// name>`, or `dir:<lowercased address>` so the three can never collide.
    fn key(&self) -> String {
        match self {
            Item::Address(address) => address.address.to_lowercase(),
            Item::List(list) => format!("list:{}", list.name.to_lowercase()),
            Item::Directory(person) => format!("dir:{}", person.address.trim().to_lowercase()),
        }
    }

    fn matches(&self, filter: &str) -> bool {
        filter.is_empty()
            || match self {
                Item::Address(address) => address.display_label().to_lowercase().contains(filter) || address.address.to_lowercase().contains(filter),
                Item::List(list) => list.name.to_lowercase().contains(filter),
                Item::Directory(person) => {
                    person.address.to_lowercase().contains(filter)
                        || person.name.as_deref().is_some_and(|name| name.to_lowercase().contains(filter))
                        || person.company.as_deref().is_some_and(|company| company.to_lowercase().contains(filter))
                        || person.title.as_deref().is_some_and(|title| title.to_lowercase().contains(filter))
                }
            }
    }

    /// The dim subtitle under the label, or `None` when the label says it all.
    fn subtitle(&self) -> Option<String> {
        match self {
            // A contact with no separate display name would otherwise show its
            // address twice.
            Item::Address(address) => (address.display_label() != address.address).then(|| address.address.clone()),
            Item::List(list) => Some(format!("Contact list · {} people", list.members.len())),
            Item::Directory(person) => Some(directory_subtitle(person)),
        }
    }

    fn into_suggestion(self) -> Suggestion {
        match self {
            Item::Address(address) => Suggestion::Address(address),
            Item::List(list) => Suggestion::List(list),
            Item::Directory(person) => Suggestion::Directory(person),
        }
    }
}

/// A directory hit's row label: the display name when there is one, else its
/// address.
fn directory_name(person: &DirectoryPerson) -> String {
    person
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| person.address.trim().to_string())
}

/// A directory hit's row caption, flagging it as a directory (not a stored
/// contact) and adding the company or job title when the entry carries one.
fn directory_subtitle(person: &DirectoryPerson) -> String {
    let detail = person
        .company
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| person.title.as_deref().map(str::trim).filter(|value| !value.is_empty()));
    match detail {
        Some(detail) => format!("Directory · {detail}"),
        None => "Directory".to_string(),
    }
}

/// Presents the modal "Add Recipients" picker, `transient_for` whichever
/// window `anchor` currently lives in (the main window or a popped-out
/// composer). `on_add` fires once, with every checked contact, when "Add" is
/// clicked; Cancel or closing the window without adding calls nothing.
///
/// `directory` is the composer's directory lookup (item 4.7.7), or `None` when
/// no directory is configured. Once the search box has text it is queried and
/// its hits appear as read-only rows under a **Directory** header; picking one
/// adds its address like any other contact.
pub fn show_contact_picker(anchor: &gtk::Widget, state: Rc<RefCell<UiState>>, directory: Option<DirectoryLookup>, on_add: Rc<dyn Fn(Vec<Suggestion>)>) {
    let mut contacts: Vec<EmailAddress> = state.borrow().contacts_by_account.values().flat_map(|snapshot| snapshot.suggestions.clone()).collect();
    contacts = dedupe_addresses(contacts, usize::MAX);
    contacts.sort_by_cached_key(|a| a.display_label().to_lowercase());

    let lists: Vec<ContactList> = {
        let mut seen = HashSet::new();
        let mut lists: Vec<ContactList> = state
            .borrow()
            .contacts_by_account
            .values()
            .flat_map(|snapshot| snapshot.contact_lists.clone())
            .filter(|list| !list.name.trim().is_empty() && seen.insert(list.name.to_lowercase()))
            .collect();
        lists.sort_by_cached_key(|list| list.name.to_lowercase());
        lists
    };

    let mut items: Vec<Item> = contacts.into_iter().map(Item::Address).collect();
    items.extend(lists.into_iter().map(Item::List));

    let dialog = {
        let mut builder = gtk::Window::builder().modal(true).title("Address Book").default_width(760).default_height(560);
        if let Some(win) = anchor.root().and_downcast::<gtk::Window>() {
            builder = builder.transient_for(&win);
        }
        builder.build()
    };

    let gal_paths = crate::oab_cache::local_paths(&state, None);
    let search = gtk::SearchEntry::builder()
        .placeholder_text(if gal_paths.is_empty() { "Search name or email (at least 3 characters)" } else { "Search name, email or department" })
        .margin_start(12)
        .margin_end(12)
        .margin_top(12)
        .build();

    // Checked items outlive their visible rows and the current filter.
    let selected: Rc<RefCell<HashMap<String, Item>>> = Rc::new(RefCell::new(HashMap::new()));
    let count_label = gtk::Label::builder().label("0 selected").css_classes(["dim-label"]).build();
    let store = gio::ListStore::new::<glib::BoxedAnyObject>();
    let list = build_picker_list(&store, &selected, &count_label);
    let scroller = gtk::ScrolledWindow::builder()
        .child(&list)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .margin_start(12)
        .margin_end(12)
        .margin_top(6)
        .build();

    let directory_items: Rc<RefCell<Vec<Item>>> = Rc::new(RefCell::new(Vec::new()));
    let status = gtk::Label::builder().xalign(0.0).css_classes(["dim-label"])
        .margin_start(12).margin_end(12).margin_top(6).build();
    let generation = Rc::new(Cell::new(0u64));
    let alive = Rc::new(Cell::new(true));
    dialog.connect_close_request({
        let alive = alive.clone();
        move |_| { alive.set(false); glib::Propagation::Proceed }
    });

    let rebuild: Rc<dyn Fn(&str)> = {
        let store = store.clone();
        let directory_items = directory_items.clone();
        Rc::new(move |query| {
            let filter = query.trim().to_lowercase();
            let local = items.iter().filter(|item| item.matches(&filter));
            let hits = directory_items.borrow();
            let mut rows: Vec<glib::BoxedAnyObject> = local.cloned()
                .map(|item| glib::BoxedAnyObject::new(PickerRow::Item(item))).collect();
            if !hits.is_empty() {
                rows.push(glib::BoxedAnyObject::new(PickerRow::Header("Global Address List")));
                rows.extend(hits.iter().cloned().map(|item| glib::BoxedAnyObject::new(PickerRow::Item(item))));
            }
            store.splice(0, store.n_items(), &rows);
        })
    };

    // The remote lookup remains available without an OAB, and as a fallback
    // when a local query has no hits or the snapshot cannot be read.
    let load: Rc<dyn Fn(String)> = {
        let rebuild = rebuild.clone();
        let directory_items = directory_items.clone();
        let generation = generation.clone();
        let alive = alive.clone();
        let status = status.clone();
        Rc::new(move |query| {
            let query = query.trim().to_owned();
            let token = generation.get().wrapping_add(1);
            generation.set(token);
            directory_items.borrow_mut().clear();
            rebuild(&query);
            let remote: Rc<dyn Fn()> = {
                let directory = directory.clone();
                let query = query.clone();
                let generation = generation.clone();
                let alive = alive.clone();
                let status = status.clone();
                let directory_items = directory_items.clone();
                let rebuild = rebuild.clone();
                Rc::new(move || {
                    let Some(lookup) = directory.as_ref().filter(|_| query.chars().count() >= crate::directory::DIRECTORY_MIN_CHARS) else {
                        status.set_label(if query.is_empty() { "Search the directory by name or email" } else { "No directory matches" });
                        return;
                    };
                    status.set_label("Searching directory…");
                    lookup(&query, Rc::new({
                        let query = query.clone();
                        let generation = generation.clone();
                        let alive = alive.clone();
                        let status = status.clone();
                        let directory_items = directory_items.clone();
                        let rebuild = rebuild.clone();
                        move |suggestions| {
                            if !alive.get() || generation.get() != token { return; }
                            let hits: Vec<Item> = suggestions.into_iter().filter_map(|s| match s {
                                Suggestion::Directory(person) => Some(Item::Directory(person)),
                                _ => None,
                            }).collect();
                            status.set_label(&format!("Directory: {}", hits.len()));
                            *directory_items.borrow_mut() = hits;
                            rebuild(&query);
                        }
                    }));
                })
            };
            if gal_paths.is_empty() { remote(); return; }
            status.set_label("Loading GAL…");
            let (tx, rx) = async_channel::bounded(1);
            let paths = gal_paths.clone();
            let query_for_read = query.clone();
            std::thread::spawn(move || {
                let result = crate::oab_cache::page(&paths, &query_for_read, 0, i64::MAX as usize);
                let _ = tx.send_blocking(result);
            });
            let generation = generation.clone();
            let alive = alive.clone();
            let directory_items = directory_items.clone();
            let status = status.clone();
            let rebuild = rebuild.clone();
            glib::spawn_future_local(async move {
                let result = rx.recv().await;
                if !alive.get() || generation.get() != token { return; }
                match result {
                    Ok(Ok(page)) => {
                        status.set_label(&format!("GAL: {}", page.total));
                        *directory_items.borrow_mut() = page.people.into_iter().map(Item::Directory).collect();
                        rebuild(&query);
                        if directory_items.borrow().is_empty() && query.chars().count() >= crate::directory::DIRECTORY_MIN_CHARS {
                            remote();
                        }
                    }
                    _ => {
                        status.set_label("Could not read local GAL");
                        if query.chars().count() >= crate::directory::DIRECTORY_MIN_CHARS { remote(); }
                    }
                }
            });
        })
    };
    search.connect_search_changed({
        let load = load.clone();
        move |entry| load(entry.text().to_string())
    });
    load(String::new());

    let cancel_button = gtk::Button::builder().label("Cancel").build();
    let add_button = gtk::Button::builder().label("Add").css_classes(["suggested-action"]).build();
    {
        let dialog = dialog.clone();
        cancel_button.connect_clicked(move |_| dialog.close());
    }
    {
        let dialog = dialog.clone();
        add_button.connect_clicked(move |_| {
            let mut picked_items: Vec<Item> = selected.borrow().values().cloned().collect();
            picked_items.sort_by_cached_key(|item| item.label().to_lowercase());
            let picked: Vec<Suggestion> = picked_items.into_iter().map(Item::into_suggestion).collect();
            dialog.close();
            if !picked.is_empty() {
                on_add(picked);
            }
        });
    }
    let action_row = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(6)
        .halign(gtk::Align::End)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .build();
    action_row.append(&count_label);
    action_row.append(&cancel_button);
    action_row.append(&add_button);

    let root = gtk::Box::builder().orientation(gtk::Orientation::Vertical).build();
    let heading = gtk::Label::builder().label("Address Book — Contacts and Global Address List").xalign(0.0).margin_start(12).margin_top(12).css_classes(["heading"]).build();
    root.append(&heading);
    root.append(&search);
    root.append(&status);
    root.append(&scroller);
    root.append(&action_row);
    dialog.set_child(Some(&root));
    dialog.present();
    search.grab_focus();
}

/// Data-only model. GtkListView owns a bounded pool of actual row widgets.
#[derive(Clone)]
enum PickerRow {
    Header(&'static str),
    Item(Item),
}

fn build_picker_list(
    store: &gio::ListStore,
    selected: &Rc<RefCell<HashMap<String, Item>>>,
    count: &gtk::Label,
) -> gtk::ListView {
    let factory = gtk::SignalListItemFactory::new();
    // Guard programmatic set_active during bind, never interpreting a recycled
    // checkbox's old state as a new user selection.
    let binding = Rc::new(Cell::new(false));
    factory.connect_setup({
        let selected = selected.clone();
        let count = count.clone();
        let binding = binding.clone();
        move |_, object| {
            let Some(item) = object.downcast_ref::<gtk::ListItem>() else { return };
            let row = gtk::Box::builder().orientation(gtk::Orientation::Horizontal)
                .spacing(8).margin_top(6).margin_bottom(6).margin_start(10).margin_end(10).build();
            let check = gtk::CheckButton::builder().valign(gtk::Align::Center).build();
            let text = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(2)
                .hexpand(true).valign(gtk::Align::Center).build();
            let name = gtk::Label::builder().xalign(0.0).ellipsize(gtk::pango::EllipsizeMode::End).build();
            let subtitle = gtk::Label::builder().xalign(0.0).ellipsize(gtk::pango::EllipsizeMode::End)
                .css_classes(["dim-label", "caption"]).build();
            crate::privacy::mark(&name);
            crate::privacy::mark(&subtitle);
            text.append(&name);
            text.append(&subtitle);
            row.append(&check);
            row.append(&text);
            item.set_child(Some(&row));

            let weak_item = item.downgrade();
            let selected = selected.clone();
            let count = count.clone();
            let binding = binding.clone();
            check.connect_toggled(move |check| {
                if binding.get() { return; }
                let Some(item) = weak_item.upgrade() else { return };
                let Some(object) = item.item().and_downcast::<glib::BoxedAnyObject>() else { return };
                let row = object.borrow::<PickerRow>();
                let PickerRow::Item(candidate) = &*row else { return };
                let mut selected = selected.borrow_mut();
                if check.is_active() { selected.insert(candidate.key(), candidate.clone()); }
                else { selected.remove(&candidate.key()); }
                count.set_label(&format!("{} selected", selected.len()));
            });
            let click = gtk::GestureClick::new();
            let weak_check = check.downgrade();
            click.connect_released(move |_, _, _, _| {
                if let Some(check) = weak_check.upgrade() {
                    if check.is_visible() { check.set_active(!check.is_active()); }
                }
            });
            text.add_controller(click);
        }
    });
    factory.connect_bind({
        let selected = selected.clone();
        let binding = binding.clone();
        move |_, object| {
            let Some(item) = object.downcast_ref::<gtk::ListItem>() else { return };
            let Some(model) = item.item().and_downcast::<glib::BoxedAnyObject>() else { return };
            let Some(row) = item.child().and_downcast::<gtk::Box>() else { return };
            let Some(check) = row.first_child().and_downcast::<gtk::CheckButton>() else { return };
            let Some(text) = row.last_child().and_downcast::<gtk::Box>() else { return };
            let Some(name) = text.first_child().and_downcast::<gtk::Label>() else { return };
            let Some(subtitle) = text.last_child().and_downcast::<gtk::Label>() else { return };
            let model = model.borrow::<PickerRow>();
            binding.set(true);
            match &*model {
                PickerRow::Header(label) => {
                    check.set_visible(false);
                    check.set_active(false);
                    name.set_label(label);
                    name.add_css_class("heading");
                    subtitle.set_visible(false);
                }
                PickerRow::Item(candidate) => {
                    check.set_visible(true);
                    check.set_active(selected.borrow().contains_key(&candidate.key()));
                    name.remove_css_class("heading");
                    name.set_label(&candidate.label());
                    let detail = candidate.subtitle();
                    subtitle.set_label(detail.as_deref().unwrap_or(""));
                    subtitle.set_visible(detail.is_some());
                }
            }
            binding.set(false);
        }
    });
    let selection = gtk::NoSelection::new(Some(store.clone()));
    gtk::ListView::new(Some(selection), Some(factory))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person() -> DirectoryPerson {
        DirectoryPerson {
            id: Some("graph-id".to_string()),
            name: Some("Grace Hopper".to_string()),
            address: "grace@example.com".to_string(),
            title: Some("Admiral".to_string()),
            company: Some("US Navy".to_string()),
        }
    }

    #[test]
    fn a_directory_item_labels_keys_and_matches_on_every_field() {
        let item = Item::Directory(person());
        assert_eq!(item.label(), "Grace Hopper");
        assert_eq!(item.key(), "dir:grace@example.com");
        assert_eq!(item.subtitle().as_deref(), Some("Directory · US Navy"));
        assert!(item.matches(""));
        assert!(item.matches("grace"));
        assert!(item.matches("hopper"));
        assert!(item.matches("navy"));
        assert!(item.matches("admiral"));
        assert!(!item.matches("zzz"));
    }

    #[test]
    fn a_directory_item_falls_back_to_the_address_and_falls_back_for_its_caption() {
        let nameless = DirectoryPerson {
            name: Some("   ".to_string()),
            title: None,
            company: None,
            ..person()
        };
        let item = Item::Directory(nameless);
        assert_eq!(item.label(), "grace@example.com");
        assert_eq!(item.subtitle().as_deref(), Some("Directory"));
        // The title stands in when there is no company to show.
        let titled = DirectoryPerson { company: None, ..person() };
        assert_eq!(Item::Directory(titled).subtitle().as_deref(), Some("Directory · Admiral"));
    }

    #[test]
    fn a_directory_item_commits_as_a_directory_suggestion() {
        let item = Item::Directory(person());
        assert_eq!(item.into_suggestion(), Suggestion::Directory(person()));
    }
}
