//! The signature editor: Config → Accounts → "New Signature…" opens a modal
//! rich-text editor (the same contenteditable WebKit editor the composer
//! uses), and saving writes through to the shared `AppConfig` (and
//! `app_config::save`) and fires `on_changed` so the settings screen's
//! signature list can refresh - the same write-through pattern as the
//! manage-identities and manage-tags dialogs.

/// Copyright (C) <2026>  <Gavin Graham & Contributors>
/// Software released under the GPL3 license
use std::cell::RefCell;
use std::rc::Rc;

use adw::prelude::*;
use base64::Engine;
use lookout_core::Signature;

use crate::app_config::AppConfig;

/// Manage the saved signatures and the two per-account defaults in a
/// single embedded dialog, without leaving the active composer.
pub(crate) fn show_manager(
    anchor: &gtk::Widget,
    app_config: Rc<RefCell<AppConfig>>,
    mut accounts: Vec<(lookout_core::AccountId, String)>,
    selected_account: Option<lookout_core::AccountId>,
    on_changed: Rc<dyn Fn()>,
) {
    accounts.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.0.cmp(&b.0.0)));
    let accounts = Rc::new(accounts);
    let Some(parent) = anchor.clone().downcast::<gtk::Window>().ok()
        .or_else(|| anchor.root().and_downcast::<gtk::Window>()) else {
        tracing::warn!("signature manager: missing parent window");
        return;
    };
    let dialog = adw::Dialog::builder().title("Signatures and Stationery")
        .content_width(780).content_height(520).build();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    dialog.set_child(Some(&toolbar));
    let root = gtk::Box::builder().orientation(gtk::Orientation::Vertical)
        .spacing(12).margin_top(16).margin_bottom(16).margin_start(16).margin_end(16).build();
    let columns = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(16).vexpand(true).build();
    let left = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(8).width_request(240).build();
    let title = gtk::Label::builder().label("Select signature to edit").xalign(0.0).css_classes(["heading"]).build();
    left.append(&title);
    let list = gtk::ListBox::builder().selection_mode(gtk::SelectionMode::Single).css_classes(["boxed-list"]).build();
    let scroller = gtk::ScrolledWindow::builder().child(&list).vexpand(true).min_content_height(160)
        .hscrollbar_policy(gtk::PolicyType::Never).build();
    left.append(&scroller);
    let actions = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let new_button = gtk::Button::with_label("New…");
    let edit_button = gtk::Button::with_label("Edit…");
    let delete_button = gtk::Button::with_label("Delete");
    delete_button.add_css_class("destructive-action");
    actions.append(&new_button); actions.append(&edit_button); actions.append(&delete_button);
    left.append(&actions);
    columns.append(&left);

    let right = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(8).hexpand(true).build();
    let defaults_title = gtk::Label::builder().label("Choose default signature").xalign(0.0).css_classes(["heading"]).build();
    right.append(&defaults_title);
    let account_names: Vec<&str> = accounts.iter().map(|(_, name)| name.as_str()).collect();
    let account = gtk::DropDown::from_strings(&account_names);
    crate::privacy::mark_content(&account);
    let account_line = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    account_line.append(&gtk::Label::new(Some("E-mail account:")));
    account.set_hexpand(true);
    account_line.append(&account);
    right.append(&account_line);
    if let Some(index) = accounts.iter().position(|(id, _)| Some(id) == selected_account.as_ref()) {
        account.set_selected(index as u32);
    }
    // AdwComboRow is an AdwPreferencesRow/GtkListBoxRow and requires
    // a GtkListBox parent for its layout and activation behavior.
    let defaults = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();
    right.append(&defaults);
    let preview_title = gtk::Label::builder().label("Signature preview").xalign(0.0).css_classes(["heading"]).margin_top(12).build();
    right.append(&preview_title);
    let preview = gtk::TextView::builder().editable(false).cursor_visible(false).wrap_mode(gtk::WrapMode::WordChar)
        .left_margin(8).right_margin(8).top_margin(8).bottom_margin(8).build();
    crate::privacy::mark_content(&preview);
    crate::compose::bind_plain_page_theme(&preview);
    let preview_scroll = gtk::ScrolledWindow::builder().child(&preview).vexpand(true).min_content_height(120).build();
    right.append(&preview_scroll);
    columns.append(&right);
    root.append(&columns);
    let done = gtk::Button::with_label("Done");
    done.add_css_class("suggested-action");
    done.set_halign(gtk::Align::End);
    root.append(&done);
    toolbar.set_content(Some(&root));

    let ids: Rc<RefCell<Vec<uuid::Uuid>>> = Rc::new(RefCell::new(Vec::new()));
    let selected_id: Rc<dyn Fn() -> Option<uuid::Uuid>> = {
        let list = list.clone(); let ids = ids.clone();
        Rc::new(move || list.selected_row().and_then(|r| ids.borrow().get(r.index() as usize).copied()))
    };
    let refresh_selection: Rc<dyn Fn()> = {
        let selected_id = selected_id.clone(); let app_config = app_config.clone();
        let preview = preview.clone(); let edit_button = edit_button.clone(); let delete_button = delete_button.clone();
        Rc::new(move || {
            let selected = selected_id().and_then(|id| app_config.borrow().signatures.iter().find(|s| s.id == id).cloned());
            edit_button.set_sensitive(selected.is_some()); delete_button.set_sensitive(selected.is_some());
            preview.buffer().set_text(selected.as_ref().map(|s| s.text.as_str()).unwrap_or(""));
        })
    };
    let refresh_defaults: Rc<dyn Fn()> = {
        let defaults = defaults.clone(); let account = account.clone(); let accounts = accounts.clone();
        let app_config = app_config.clone(); let on_changed = on_changed.clone();
        Rc::new(move || {
            while let Some(child) = defaults.first_child() { defaults.remove(&child); }
            let Some((id, _)) = accounts.get(account.selected() as usize) else {
                defaults.set_placeholder(Some(&gtk::Label::new(Some("No mail account available"))));
                return;
            };
            let (signatures, current) = {
                let cfg = app_config.borrow();
                (cfg.signatures.clone(), cfg.signature_defaults.get(id).cloned().unwrap_or_default())
            };
            let set: crate::config_view::SetAccountSignatureDefault = {
                let app_config = app_config.clone(); let on_changed = on_changed.clone();
                Rc::new(move |account, kind, signature| {
                    let mut cfg = app_config.borrow_mut();
                    let entry = cfg.signature_defaults.entry(lookout_core::AccountId(account.to_owned())).or_default();
                    match kind {
                        crate::config_view::SignatureDefault::New => entry.new = signature,
                        crate::config_view::SignatureDefault::Reply => entry.reply = signature,
                    }
                    crate::app_config::save(&cfg);
                    drop(cfg);
                    on_changed();
                })
            };
            for (title, value, kind) in [
                ("New messages", current.new, crate::config_view::SignatureDefault::New),
                ("Replies & forwards", current.reply, crate::config_view::SignatureDefault::Reply),
            ] {
                let row = crate::config_view::signature_default_dropdown(title, "", &id.0, value, &signatures, kind, &set);
                defaults.append(&row);
            }
        })
    };
    let refresh: Rc<dyn Fn()> = {
        let list = list.clone(); let ids = ids.clone(); let app_config = app_config.clone();
        let selected_id = selected_id.clone(); let refresh_selection = refresh_selection.clone(); let refresh_defaults = refresh_defaults.clone();
        Rc::new(move || {
            let previous = selected_id();
            let signatures = app_config.borrow().signatures.clone();
            while let Some(child) = list.first_child() { list.remove(&child); }
            *ids.borrow_mut() = signatures.iter().map(|s| s.id).collect();
            for signature in &signatures {
                let label = gtk::Label::builder().label(&signature.name).xalign(0.0).ellipsize(gtk::pango::EllipsizeMode::End)
                    .margin_top(6).margin_bottom(6).margin_start(8).margin_end(8).build();
                crate::privacy::mark_content(&label);
                list.append(&label);
            }
            let index = signatures.iter().position(|s| Some(s.id) == previous).unwrap_or(0);
            if let Some(row) = list.row_at_index(index as i32) { list.select_row(Some(&row)); }
            refresh_selection(); refresh_defaults();
        })
    };
    {
        let refresh_selection = refresh_selection.clone();
        list.connect_row_selected(move |_, _| refresh_selection());
        let refresh_defaults = refresh_defaults.clone();
        account.connect_selected_notify(move |_| refresh_defaults());
    }
    let changed: Rc<dyn Fn()> = {
        let refresh = refresh.clone(); let on_changed = on_changed.clone();
        Rc::new(move || { refresh(); on_changed(); })
    };
    {
        let app_config = app_config.clone(); let changed = changed.clone();
        new_button.connect_clicked(move |button| show_editor_dialog(button.upcast_ref(), app_config.clone(), None, changed.clone()));
    }
    {
        let app_config = app_config.clone(); let changed = changed.clone(); let selected_id = selected_id.clone();
        edit_button.connect_clicked(move |button| {
            let existing = selected_id().and_then(|id| app_config.borrow().signatures.iter().find(|s| s.id == id).cloned());
            if let Some(existing) = existing { show_editor_dialog(button.upcast_ref(), app_config.clone(), Some(existing), changed.clone()); }
        });
    }
    {
        let edit_button = edit_button.clone();
        list.connect_row_activated(move |_, _| edit_button.emit_clicked());
    }
    {
        let app_config = app_config.clone(); let changed = changed.clone(); let selected_id = selected_id.clone();
        delete_button.connect_clicked(move |_| {
            let Some(id) = selected_id() else { return };
            app_config.borrow_mut().remove_signature(&id);
            crate::app_config::save(&app_config.borrow());
            changed();
        });
    }
    {
        let dialog = dialog.clone();
        done.connect_clicked(move |_| { dialog.close(); });
    }
    refresh();
    tracing::debug!("signature manager: presenting embedded dialog");
    dialog.present(Some(&parent));
}

/// Presents the modal signature editor, anchored to `anchor`'s window when
/// one exists (tests have no window). `existing` prefills the editor (the
/// edit path); `None` starts a blank signature (the add path). `on_changed`
/// fires after every persisted change so live views of the signature list
/// can refresh.
pub fn show_editor_dialog(anchor: &gtk::Widget, app_config: Rc<RefCell<AppConfig>>, existing: Option<Signature>, on_changed: Rc<dyn Fn()>) {
    let dialog = {
        let mut builder = gtk::Window::builder()
            .modal(true)
            .title(if existing.is_some() { "Edit signature" } else { "New signature" })
            .default_width(720)
            .default_height(560);
        if let Some(win) = anchor.root().and_downcast::<gtk::Window>() {
            builder = builder.transient_for(&win);
        }
        builder.build()
    };

    let name_entry = gtk::Entry::builder()
        .placeholder_text("Name (e.g. Work, Personal)")
        .text(existing.as_ref().map(|s| s.name.as_str()).unwrap_or(""))
        .build();
    let (web_view, format_controls) = crate::compose::build_rich_editor(existing.as_ref().map(|s| s.html.clone()).unwrap_or_default());

    let toolbar = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(6).css_classes(["toolbar"]).build();
    toolbar.append(&format_controls.strip());
    toolbar.append(&crate::compose::page_background_button());
    let rich_scroller = gtk::ScrolledWindow::builder().child(&*web_view).hexpand(true).vexpand(true).build();

    let save_button = gtk::Button::with_label("Save");
    save_button.add_css_class("suggested-action");
    let cancel_button = gtk::Button::with_label("Cancel");
    let button_row = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(6).halign(gtk::Align::End).build();
    button_row.append(&cancel_button);
    button_row.append(&save_button);

    let root = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(8)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .build();
    root.append(&name_entry);
    root.append(&toolbar);
    root.append(&rich_scroller);
    root.append(&button_row);
    dialog.set_child(Some(&root));

    // Save stays disabled until a name is entered - the list rows are keyed
    // on the name, so an unnamed signature would be unreachable afterwards.
    save_button.set_sensitive(!name_entry.text().is_empty());
    {
        let save_button = save_button.clone();
        name_entry.connect_changed(move |entry| save_button.set_sensitive(!entry.text().is_empty()));
    }
    {
        let dialog = dialog.clone();
        cancel_button.connect_clicked(move |_| dialog.close());
    }

    let edit_id = existing.as_ref().map(|s| s.id);
    let save = {
        let dialog = dialog.clone();
        let app_config = app_config.clone();
        let on_changed = on_changed.clone();
        let name_entry = name_entry.clone();
        let web_view = web_view.clone();
        move || {
            let name = name_entry.text().trim().to_string();
            if name.is_empty() {
                return;
            }
            let dialog = dialog.clone();
            let app_config = app_config.clone();
            let on_changed = on_changed.clone();
            let web_view = web_view.clone();
            // `read_content` must stay async (it awaits the WebView's JS
            // evaluation); see `compose::read_content` for why blocking is
            // unsafe inside a glib-spawned future.
            gtk::glib::spawn_future_local(async move {
                let Some(content) = crate::compose::read_content(&web_view).await else { return };
                let signature = Signature::new(name, embed_images(&content.html, &content.images), content.text);
                {
                    let mut config = app_config.borrow_mut();
                    if let Some(id) = edit_id {
                        config.upsert_signature(Signature { id, ..signature });
                    } else {
                        config.upsert_signature(signature);
                    }
                }
                crate::app_config::save(&app_config.borrow());
                on_changed();
                dialog.close();
            });
        }
    };
    let save_for_activate = save.clone();
    save_button.connect_clicked(move |_| save());
    name_entry.connect_activate(move |_| save_for_activate());

    dialog.present();
}

/// `read_content` pulls pasted images out of the editor as `cid:`-referenced
/// `InlineImage`s (the send path turns them into MIME attachments). A
/// signature must be self-contained - nothing attaches when a signature is
/// inserted - so the images are re-embedded as `data:` URIs right in the
/// stored HTML. The round trip stays intact: the composer's paste handler
/// renders `data:` images fine, and at send time `read_content` extracts
/// them back into inline attachments again.
pub(crate) fn embed_images(html: &str, images: &[lookout_mail::InlineImage]) -> String {
    if images.is_empty() {
        return html.to_string();
    }
    let mut out = html.to_string();
    for image in images {
        let data_uri = format!("data:{};base64,{}", image.content_type, base64::engine::general_purpose::STANDARD.encode(&image.bytes));
        out = out.replace(&format!("cid:{}", image.cid), &data_uri);
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embed_images_turns_cid_references_into_data_uris() {
        let image = lookout_mail::InlineImage {
            cid: "img-1@lookout.local".to_string(),
            content_type: "image/png".to_string(),
            bytes: vec![0x89, 0x50, 0x4e, 0x47],
        };
        let html = r#"<p>Hi</p><img src="cid:img-1@lookout.local"><p>Bye</p>"#;
        let embedded = embed_images(html, &[image]);
        assert!(
            embedded.contains(r#"<img src="data:image/png;base64,iVBORw==">"#),
            "the cid reference must become an inline data URI"
        );
        assert!(!embedded.contains("cid:"), "no cid reference may survive");
        assert!(embedded.contains("<p>Hi</p>"), "the surrounding HTML must be untouched");
    }

    #[test]
    fn embed_images_without_images_returns_the_html_unchanged() {
        let html = r#"<p>Hi</p><img src="cid:nope@lookout.local">"#;
        assert_eq!(embed_images(html, &[]), html);
    }
}
