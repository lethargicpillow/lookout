//! Manual IMAP/SMTP accounts ("other accounts"): mail accounts Lookout
//! manages itself rather than sourcing from GNOME Online Accounts.
//!
//! The account list itself is relational data, so it lives in `settings.json`
//! (`AppConfig::other_accounts`) exactly like sending identities and webcal
//! subscriptions. Passwords never touch that file - they go in the GNOME
//! keyring via the Secret Service D-Bus API (`secret-service` crate, the same
//! zbus stack the GOA integration uses), one item per `(account, protocol)`,
//! addressed by stable attributes so an account's secrets can be found,
//! replaced, and deleted without ever reading them back.
//!
//! [`OtherCredentialProvider`] bridges the keyring to `lookout-mail`'s
//! `CredentialProvider` trait, mirroring `goa_credentials.rs`: a fresh
//! password is fetched on every (re)connect attempt and SMTP send, and never
//! cached by the mail engine.

/// Copyright (C) <2026>  <Gavin Graham & Contributors>
/// Software released under the GPL3 license
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use adw::prelude::*;
use async_trait::async_trait;
use gtk::glib;
use lookout_core::AccountId;
use lookout_mail::session::CredentialProvider;
use lookout_mail::{Credential, Protocol, Security};
use secret_service::{EncryptionType, SecretService};

use crate::app_config::{AppConfig, OtherAccount, OTHER_ACCOUNT_ID_PREFIX};
use crate::worker::Worker;

pub(crate) const PROTOCOL_IMAP: &str = "imap";
pub(crate) const PROTOCOL_SMTP: &str = "smtp";
/// The keyring slot for an LDAP directory's bind password (items 4.7.4-4.7.5 /
/// P-11). Unlike the mail slots, its item is keyed by the `LdapDirectory.id`
/// (e.g. `ldap:<uuid>`) through the same `KeyringStore` API - the "account"
/// attribute is just the id string - and `delete_account` drops it when the
/// directory is removed. Read by the LDAP backend; the Settings UI that writes
/// it is item 4.7.9.
pub(crate) const PROTOCOL_LDAP: &str = "ldap";

/// The keyring item attribute identifying Lookout's own items, so the
/// passwords show up under a recognizable application name in Seahorse and
/// are never confused with another app's secrets.
const KEYRING_APPLICATION: &str = "io.github.gavindi.Lookout";

// ---------------------------------------------------------------------------
// Keyring access
// ---------------------------------------------------------------------------

/// Where an account's passwords are stored and how they're fetched. Behind a
/// trait so the credential provider and the account dialog are testable
/// against a fake store (no D-Bus/secret service daemon in CI). Implemented
/// by [`SecretServiceKeyring`] in production.
#[async_trait]
pub trait KeyringStore: Send + Sync {
    /// The stored password for `account_id`'s protocol slot (`imap`/`smtp`).
    async fn load_password(&self, account_id: &AccountId, protocol: &str) -> Result<String, String>;
    /// Stores (or replaces) the password for one protocol slot.
    async fn store_password(&self, account_id: &AccountId, protocol: &str, password: &str) -> Result<(), String>;
    /// Removes every stored secret for `account_id` (both protocol slots).
    async fn delete_account(&self, account_id: &AccountId) -> Result<(), String>;
}

/// The production keyring: GNOME Keyring / any Secret Service provider,
/// reached over the session D-Bus. Stateless - each call opens its own
/// connection, matching the "fetch fresh credentials per attempt" philosophy
/// of the GOA bridge. `Send + Sync`, so one `Arc` can be shared between the
/// UI-thread dialog, the worker-thread credential fetches, and removal.
pub struct SecretServiceKeyring;

impl SecretServiceKeyring {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Arc<dyn KeyringStore> {
        Arc::new(SecretServiceKeyring)
    }
}

/// The lookup attributes for one account's protocol slot. Every operation
/// addresses items by these, never by label.
fn slot_attributes<'a>(account_id: &'a AccountId, protocol: &'a str) -> HashMap<&'a str, &'a str> {
    let mut attrs = HashMap::new();
    attrs.insert("application", KEYRING_APPLICATION);
    attrs.insert("account", account_id.0.as_str());
    attrs.insert("protocol", protocol);
    attrs
}

/// All of an account's items (both protocol slots): `application` + `account`
/// match anything the account owns regardless of protocol.
fn account_attributes(account_id: &AccountId) -> HashMap<&str, &str> {
    let mut attrs = HashMap::new();
    attrs.insert("application", KEYRING_APPLICATION);
    attrs.insert("account", account_id.0.as_str());
    attrs
}

/// Turns a `secret-service` error into a user-facing message. The exotic
/// cases (no provider on the bus, no default collection, a dismissed
/// unlock prompt) get explicit explanations because they're the ones the
/// user can actually do something about. Shared with `assistant.rs`, which
/// stores the Assistant API token in the same keyring.
pub(crate) fn keyring_error(e: secret_service::Error) -> String {
    match e {
        secret_service::Error::Unavailable => {
            "No keyring is available - enable a Secret Service provider (KWallet's Secret Service integration on KDE, or gnome-keyring elsewhere) to store account passwords."
                .to_string()
        }
        secret_service::Error::NoResult => "The keyring has no default collection - create one (for example with Seahorse) to store account passwords.".to_string(),
        secret_service::Error::Prompt => "The keyring unlock prompt was dismissed.".to_string(),
        secret_service::Error::Locked => "The keyring is locked - unlock it to access stored passwords.".to_string(),
        other => format!("Keyring error: {other}"),
    }
}

#[async_trait]
impl KeyringStore for SecretServiceKeyring {
    async fn load_password(&self, account_id: &AccountId, protocol: &str) -> Result<String, String> {
        let service = SecretService::connect(EncryptionType::Dh).await.map_err(keyring_error)?;
        let collection = service.get_default_collection().await.map_err(keyring_error)?;
        let items = collection.search_items(slot_attributes(account_id, protocol)).await.map_err(keyring_error)?;
        let Some(item) = items.into_iter().next() else {
            return Err(format!("No saved password for {} ({protocol}).", account_id.0));
        };
        let secret = item.get_secret().await.map_err(keyring_error)?;
        String::from_utf8(secret).map_err(|_| "The stored password is not valid text.".to_string())
    }

    async fn store_password(&self, account_id: &AccountId, protocol: &str, password: &str) -> Result<(), String> {
        let service = SecretService::connect(EncryptionType::Dh).await.map_err(keyring_error)?;
        let collection = service.get_default_collection().await.map_err(keyring_error)?;
        // Best-effort unlock: a locked default collection prompts the user
        // through the keyring daemon before the write lands.
        let _ = collection.unlock().await;
        collection
            .create_item(
                &format!("Lookout · {} · {}", account_id.0, protocol),
                slot_attributes(account_id, protocol),
                password.as_bytes(),
                true,
                "text/plain",
            )
            .await
            .map_err(keyring_error)?;
        Ok(())
    }

    async fn delete_account(&self, account_id: &AccountId) -> Result<(), String> {
        let service = SecretService::connect(EncryptionType::Dh).await.map_err(keyring_error)?;
        let collection = service.get_default_collection().await.map_err(keyring_error)?;
        let items = collection.search_items(account_attributes(account_id)).await.map_err(keyring_error)?;
        for item in items {
            item.delete().await.map_err(keyring_error)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Credential provider
// ---------------------------------------------------------------------------

/// Feeds `lookout-mail` the keyring-stored password for one manual account.
/// Both protocol slots always exist (the save flow writes the same password
/// into both when the user opted for a single password), so IMAP and SMTP
/// each read their own slot - the `use_same_password` flag is purely a
/// dialog convenience and never consulted at connect time.
pub struct OtherCredentialProvider {
    account_id: AccountId,
    keyring: Arc<dyn KeyringStore>,
}

impl OtherCredentialProvider {
    pub fn new(account_id: AccountId, keyring: Arc<dyn KeyringStore>) -> Self {
        OtherCredentialProvider { account_id, keyring }
    }
}

#[async_trait]
impl CredentialProvider for OtherCredentialProvider {
    async fn imap_credential(&self) -> Result<Credential, String> {
        let password = self.keyring.load_password(&self.account_id, PROTOCOL_IMAP).await?;
        Ok(Credential::Password(password))
    }

    async fn smtp_credential(&self) -> Result<Credential, String> {
        let password = self.keyring.load_password(&self.account_id, PROTOCOL_SMTP).await?;
        Ok(Credential::Password(password))
    }
}

/// Recognize the conventional local DavMail profile, never remote IMAP.
pub(crate) fn davmail_accounts(account: &OtherAccount) -> Option<(lookout_goa::GoaCalendarAccount, lookout_goa::GoaContactsAccount)> {
    let local = |host: &str| host == "127.0.0.1" || host.eq_ignore_ascii_case("localhost");
    if !local(&account.imap_host) || !local(&account.smtp_host)
        || account.imap_port != 1143 || account.smtp_port != 1025
        || account.resolved_imap_security() != Security::Plain
        || account.resolved_smtp_security() != Security::Plain
        || account.email.trim().is_empty() || account.imap_username.trim().is_empty()
    {
        return None;
    }
    let mut url = reqwest::Url::parse("http://127.0.0.1:1080/").ok()?;
    {
        let mut path = url.path_segments_mut().ok()?;
        path.pop_if_empty().push("users").push(&account.email).push("calendar").push("");
    }
    let calendar_uri = url.to_string();
    {
        let mut path = url.path_segments_mut().ok()?;
        path.pop_if_empty().pop().push("contacts").push("");
    }
    let contacts_uri = url.to_string();
    let account_id = AccountId(account.id.clone());
    let display_name = if account.display_name.is_empty() { account.email.clone() } else { account.display_name.clone() };
    // Reuse the existing DAV account metadata; the root object path is a
    // placeholder, never used for D-Bus authentication by manual sessions.
    Some((
        lookout_goa::GoaCalendarAccount {
            account_id: account_id.clone(),
            object_path: "/".try_into().expect("valid root object path"),
            display_name: display_name.clone(),
            identity: account.imap_username.clone(),
            uri: calendar_uri,
            accept_ssl_errors: false,
            auth: lookout_goa::CalendarAuthMethod::Password { password_id: PROTOCOL_IMAP.into() },
            provider_type: None,
        },
        lookout_goa::GoaContactsAccount {
            account_id,
            object_path: "/".try_into().expect("valid root object path"),
            display_name,
            identity: account.imap_username.clone(),
            uri: contacts_uri,
            accept_ssl_errors: false,
            auth: lookout_goa::ContactsAuthMethod::Password { password_id: PROTOCOL_IMAP.into() },
            provider_type: None,
        },
    ))
}

#[async_trait]
impl lookout_dav::session::CalendarCredentialProvider for OtherCredentialProvider {
    async fn calendar_credential(&self) -> Result<lookout_dav::Credential, String> {
        self.keyring.load_password(&self.account_id, PROTOCOL_IMAP).await.map(lookout_dav::Credential::Password)
    }
}

// ---------------------------------------------------------------------------
// Add/edit dialog
// ---------------------------------------------------------------------------

/// Opens the add-account (or edit-account) dialog for one manual IMAP/SMTP
/// account, anchored to `anchor`'s window when one exists (tests have no
/// window). `existing` is `None` for a new account. Passwords are never
/// loaded back out of the keyring for display - on edit the password fields
/// start blank, and blank means "keep the stored secrets", so changing
/// server settings never requires re-typing the password.
///
/// `prefill` seeds a *new* account's fields (its id is ignored and a fresh
/// one is generated on save) - the Evolution import (EDS_TODO.md E3.4) uses it
/// for accounts whose password it couldn't find. It's ignored when `existing`
/// is set.
///
/// On a successful save (`on_saved` fires on the UI thread with the account
/// id, after both the keyring write and the `settings.json` write have
/// landed) the caller connects or reconnects the account. Returns the dialog,
/// so a caller can tell when it closes.
pub fn show_add_account_dialog(
    anchor: &gtk::Widget,
    worker: Rc<Worker>,
    app_config: Rc<RefCell<AppConfig>>,
    keyring: Arc<dyn KeyringStore>,
    existing: Option<OtherAccount>,
    prefill: Option<OtherAccount>,
    on_saved: Rc<dyn Fn(&str)>,
) -> gtk::Window {
    let is_edit = existing.is_some();
    let dialog = {
        let mut builder = gtk::Window::builder()
            .modal(true)
            .title(if is_edit { "Edit mail account" } else { "Add mail account" })
            .default_width(if is_edit { 773 } else { 640 })
            .default_height(if is_edit { 640 } else { 390 });
        if let Some(win) = anchor.root().and_downcast::<gtk::Window>() {
            builder = builder.transient_for(&win);
        }
        builder.build()
    };

    // -- form fields --
    let name_entry = gtk::Entry::builder().placeholder_text("Display name (optional)").hexpand(true).build();
    let email_entry = gtk::Entry::builder().placeholder_text("name@example.com").hexpand(true).build();

    let oab_entry = gtk::Entry::builder().placeholder_text("https://exchange.example/OAB/GUID/oab.xml").hexpand(true).build();
    if let Some(account) = existing.as_ref() {
        if let Some(url) = app_config.borrow().oab_urls.get(&account.id) { oab_entry.set_text(url); }
    }
    let imap_host_entry = gtk::Entry::builder().placeholder_text("imap.example.com").build();
    let imap_port_spin = gtk::SpinButton::with_range(1.0, 65535.0, 1.0);
    imap_port_spin.set_value(993.0);
    let imap_security_dropdown = security_dropdown(Security::ImplicitTls);
    let imap_username_entry = gtk::Entry::builder().placeholder_text("username").build();

    // SMTP defaults to mirroring IMAP (the overwhelmingly common case for
    // self-hosted mail); toggling the switch reveals its own fields.
    let same_server_switch = gtk::Switch::new();
    same_server_switch.set_active(true);
    let smtp_host_entry = gtk::Entry::builder().placeholder_text("smtp.example.com").build();
    let smtp_port_spin = gtk::SpinButton::with_range(1.0, 65535.0, 1.0);
    smtp_port_spin.set_value(587.0);
    let smtp_security_dropdown = security_dropdown(Security::StartTls);
    let smtp_username_entry = gtk::Entry::builder().placeholder_text("username").build();
    let smtp_fields_box = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(8).build();

    let same_password_switch = gtk::Switch::new();
    same_password_switch.set_active(true);
    let imap_password_entry = gtk::PasswordEntry::builder()
        .placeholder_text(if is_edit { "Leave blank to keep saved password" } else { "Password" })
        .show_peek_icon(true).hexpand(true).build();
    let smtp_password_entry = gtk::PasswordEntry::builder().placeholder_text("SMTP password").build();
    let smtp_password_box = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(8).build();

    // Seed an edit with the persisted values (never the passwords), or a new
    // account with the prefill.
    if let Some(account) = existing.as_ref().or(prefill.as_ref()) {
        name_entry.set_text(&account.display_name);
        email_entry.set_text(&account.email);
        imap_host_entry.set_text(&account.imap_host);
        imap_port_spin.set_value(account.imap_port as f64);
        imap_security_dropdown.set_selected(security_position(account.resolved_imap_security()));
        imap_username_entry.set_text(&account.imap_username);
        let same_server = account.smtp_host == account.imap_host && account.smtp_username == account.imap_username;
        same_server_switch.set_active(same_server);
        smtp_host_entry.set_text(&account.smtp_host);
        smtp_port_spin.set_value(account.smtp_port as f64);
        smtp_security_dropdown.set_selected(security_position(account.resolved_smtp_security()));
        smtp_username_entry.set_text(&account.smtp_username);
        same_password_switch.set_active(account.use_same_password);
    }

    // -- assemble the form --
    let form = gtk::Grid::builder()
        .column_spacing(12)
        .row_spacing(8)
        .halign(gtk::Align::Fill)
        .hexpand(true)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .build();

    let mut row = 0;
    let detect_button = gtk::Button::with_label("Find settings");
    detect_button.set_halign(gtk::Align::End);
    let setup_status = gtk::Label::builder().wrap(true).halign(gtk::Align::Start)
        .xalign(0.0).css_classes(["dim-label"]).visible(false).build();
    let approve_button = gtk::Button::with_label("Trust this server and continue");
    approve_button.set_visible(false);
    if !is_edit {
        let intro = gtk::Label::builder()
            .label("Enter your email and find settings. Lookout will determine how to sign in. Password-based accounts may require an app password.")
            .wrap(true).halign(gtk::Align::Start).xalign(0.0).build();
        form.attach(&intro, 0, row, 2, 1);
        row += 1;
    }
    form.attach(&field_label("Email address"), 0, row, 1, 1);
    form.attach(&email_entry, 1, row, 1, 1);
    row += 1;
    form.attach(&field_label("Password"), 0, row, 1, 1);
    form.attach(&imap_password_entry, 1, row, 1, 1);
    row += 1;
    form.attach(&field_label("Name"), 0, row, 1, 1);
    form.attach(&name_entry, 1, row, 1, 1);
    row += 1;
    if !is_edit {
        form.attach(&detect_button, 1, row, 1, 1);
        row += 1;
        form.attach(&setup_status, 0, row, 2, 1);
        row += 1;
        form.attach(&approve_button, 1, row, 1, 1);
        row += 1;
    }

    // Keep technical settings available for existing accounts and imported
    // profiles, but out of the normal email/password discovery workflow.
    let advanced = gtk::Expander::builder().label("Advanced server settings")
        .expanded(is_edit || prefill.is_some()).hexpand(true).build();
    let server_form = gtk::Grid::builder().column_spacing(12).row_spacing(8)
        .margin_top(12).hexpand(true).build();
    advanced.set_child(Some(&server_form));
    form.attach(&advanced, 0, row, 2, 1);
    row += 1;
    let error_label = gtk::Label::builder().halign(gtk::Align::Start).xalign(0.0)
        .css_classes(["error"]).wrap(true).visible(false).build();
    form.attach(&error_label, 0, row, 2, 1);

    let mut row = 0;
    server_form.attach(&field_label("IMAP server"), 0, row, 1, 1);
    server_form.attach(&imap_host_entry, 1, row, 1, 1);
    server_form.attach(&port_label("Port"), 2, row, 1, 1);
    server_form.attach(&imap_port_spin, 3, row, 1, 1);
    row += 1;
    server_form.attach(&field_label("IMAP username"), 0, row, 1, 1);
    server_form.attach(&imap_username_entry, 1, row, 1, 1);
    row += 1;
    server_form.attach(&field_label("IMAP security"), 0, row, 1, 1);
    server_form.attach(&imap_security_dropdown, 1, row, 1, 1);
    row += 1;

    let same_server_row = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(12).hexpand(true).build();
    let same_server_label = gtk::Label::builder().label("Use the same server for SMTP").hexpand(true).halign(gtk::Align::Start).build();
    crate::privacy::mark_ui(&same_server_label);
    same_server_row.append(&same_server_label);
    same_server_row.append(&same_server_switch);
    server_form.attach(&same_server_row, 1, row, 3, 1);
    row += 1;

    let smtp_host_row = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(12).build();
    smtp_host_row.append(&smtp_host_entry);
    smtp_host_row.append(&port_label("Port"));
    smtp_host_row.append(&smtp_port_spin);
    let smtp_username_row = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(12).build();
    let smtp_username_label = gtk::Label::builder().label("SMTP username").width_request(120).halign(gtk::Align::End).build();
    crate::privacy::mark_ui(&smtp_username_label);
    smtp_username_row.append(&smtp_username_label);
    smtp_username_row.append(&smtp_username_entry);
    smtp_fields_box.append(&smtp_host_row);
    smtp_fields_box.append(&smtp_username_row);
    server_form.attach(&field_label("SMTP"), 0, row, 1, 1);
    server_form.attach(&smtp_fields_box, 1, row, 3, 1);
    row += 1;
    server_form.attach(&field_label("SMTP security"), 0, row, 1, 1);
    server_form.attach(&smtp_security_dropdown, 1, row, 1, 1);
    row += 1;
    let plain_note = gtk::Label::builder()
        .label("Without encryption, your password and mail cross the network unprotected.")
        .wrap(true)
        .halign(gtk::Align::Start)
        .css_classes(["warning"])
        .build();
    crate::privacy::mark_ui(&plain_note);
    server_form.attach(&plain_note, 1, row, 3, 1);
    row += 1;

    let same_password_row = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(12).hexpand(true).build();
    let same_password_label = gtk::Label::builder()
        .label("Use the same password for sending")
        .hexpand(true)
        .halign(gtk::Align::Start)
        .build();
    crate::privacy::mark_ui(&same_password_label);
    same_password_row.append(&same_password_label);
    same_password_row.append(&same_password_switch);
    server_form.attach(&same_password_row, 1, row, 3, 1);
    row += 1;

    smtp_password_box.append(&smtp_password_entry);
    server_form.attach(&smtp_password_box, 1, row, 3, 1);
    row += 1;

    server_form.attach(&field_label("Exchange OAB URL"), 0, row, 1, 1);
    server_form.attach(&oab_entry, 1, row, 3, 1);
    row += 1;
    let oab_hint = gtk::Label::builder().label("Optional: full HTTPS manifest URL for DavMail GAL automatic updates. Uses the saved IMAP password. Clear to disable.").wrap(true).halign(gtk::Align::Start).css_classes(["dim-label"]).build();
    server_form.attach(&oab_hint, 1, row, 3, 1);

    // SMTP mirrors IMAP unless told otherwise.
    for (slave, master) in [(&smtp_host_entry, &imap_host_entry), (&smtp_username_entry, &imap_username_entry)] {
        let slave = slave.clone();
        let master = master.clone();
        let same_server_switch = same_server_switch.clone();
        master.connect_changed(move |entry| {
            if same_server_switch.is_active() {
                slave.set_text(&entry.text());
            }
        });
    }
    same_server_switch.connect_state_set({
        let host = smtp_host_entry.clone();
        let username = smtp_username_entry.clone();
        move |_switch, state| {
            // Sharing the hostname/login must not disable the SMTP port.
            host.set_sensitive(!state);
            username.set_sensitive(!state);
            glib::Propagation::Proceed
        }
    });
    same_password_switch.connect_state_set({
        let smtp_password_box = smtp_password_box.clone();
        move |_switch, state| {
            smtp_password_box.set_visible(!state);
            glib::Propagation::Proceed
        }
    });
    // `connect_state_set` only fires on user interaction, not the initial
    // `set_active` seed above - sync the dependent fields' visibility once
    // up front so an edit dialog opened with "same server"/"same password"
    // off starts with the right fields shown.
    smtp_host_entry.set_sensitive(!same_server_switch.is_active());
    smtp_username_entry.set_sensitive(!same_server_switch.is_active());
    smtp_password_box.set_visible(!same_password_switch.is_active());

    // Changing the security mode moves a standard port to the new mode's
    // (993 <-> 143, 465 <-> 587); a custom port is left alone. Hooked up after
    // the seed above so an edit keeps its saved port.
    follow_standard_port(&imap_security_dropdown, &imap_port_spin, Protocol::Imap);
    follow_standard_port(&smtp_security_dropdown, &smtp_port_spin, Protocol::Smtp);
    let sync_plain_note = {
        let plain_note = plain_note.clone();
        let imap_security_dropdown = imap_security_dropdown.clone();
        let smtp_security_dropdown = smtp_security_dropdown.clone();
        move || {
            let plain = [&imap_security_dropdown, &smtp_security_dropdown].iter().any(|d| selected_security(d) == Security::Plain);
            plain_note.set_visible(plain);
        }
    };
    sync_plain_note();
    for dropdown in [&imap_security_dropdown, &smtp_security_dropdown] {
        let sync_plain_note = sync_plain_note.clone();
        dropdown.connect_selected_notify(move |_| sync_plain_note());
    }

    // -- footer: Cancel / Save --
    let footer = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(6)
        .halign(gtk::Align::End)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .build();
    let cancel_button = gtk::Button::builder().label("Cancel").build();
    let save_button = gtk::Button::builder()
        .label(if is_edit { "Save" } else { "Add account" })
        .css_classes(["suggested-action"])
        .build();
    footer.append(&cancel_button);
    footer.append(&save_button);

    let root = gtk::Box::builder().orientation(gtk::Orientation::Vertical).build();
    let scroller = gtk::ScrolledWindow::builder().child(&form).vexpand(true).hscrollbar_policy(gtk::PolicyType::Never).build();
    root.append(&scroller);
    root.append(&footer);
    dialog.set_child(Some(&root));
    {
        let dialog = dialog.downgrade();
        advanced.connect_expanded_notify(move |expander| {
            if let Some(dialog) = dialog.upgrade() {
                if expander.is_expanded() {
                    dialog.set_default_size(773, 700);
                } else if !is_edit {
                    dialog.set_default_size(640, 390);
                }
            }
        });
    }
    // A new account needs discovery (or explicit advanced configuration)
    // before saving. Editing an existing profile retains its saved secret.
    let ready = Rc::new(std::cell::Cell::new(is_edit || prefill.is_some()));
    let running = Rc::new(std::cell::Cell::new(false));
    let refresh_actions: Rc<dyn Fn()> = {
        let email = email_entry.clone();
        let password = imap_password_entry.clone();
        let button = detect_button.clone();
        let save = save_button.clone();
        let advanced = advanced.clone();
        let ready = ready.clone();
        let running = running.clone();
        Rc::new(move || {
            let address_valid = crate::recipient_entry::is_plausible_address(email.text().trim());
            let credentials = address_valid && !password.text().is_empty();
            button.set_sensitive(!running.get() && address_valid);
            save.set_sensitive(!running.get() && (is_edit || (credentials && (ready.get() || advanced.is_expanded()))));
        })
    };
    refresh_actions();
    if !is_edit {
        let refresh = refresh_actions.clone();
        let ready = ready.clone();
        let status = setup_status.clone();
        let approve = approve_button.clone();
        let oab = oab_entry.clone();
        let name = name_entry.clone();
        let previous = Rc::new(RefCell::new(email_entry.text().trim().to_owned()));
        email_entry.connect_changed(move |entry| {
            let address = entry.text().trim().to_owned();
            let mut old = previous.borrow_mut();
            if *old != address {
                if ready.replace(false) {
                    oab.set_text("");
                    if name.text().as_str() == old.as_str() { name.set_text(""); }
                }
                *old = address;
                status.set_visible(false);
                approve.set_visible(false);
            }
            refresh();
        });
        let refresh = refresh_actions.clone();
        imap_password_entry.connect_changed(move |_| refresh());
        let refresh = refresh_actions.clone();
        advanced.connect_expanded_notify(move |_| refresh());
    }

    {
        let dialog = dialog.clone();
        cancel_button.connect_clicked(move |_| dialog.close());
    }

    if !is_edit {
        use crate::account_setup::Discovery;
        // Shared apply function: both discovery and gateway setup use the
        // exact same persisted manual-account fields, not a second account type.
        let apply = {
            let name = name_entry.clone();
            let email = email_entry.clone();
            let ih = imap_host_entry.clone();
            let ip = imap_port_spin.clone();
            let is = imap_security_dropdown.clone();
            let iu = imap_username_entry.clone();
            let sh = smtp_host_entry.clone();
            let sp = smtp_port_spin.clone();
            let ss = smtp_security_dropdown.clone();
            let su = smtp_username_entry.clone();
            let same = same_server_switch.clone();
            let same_password = same_password_switch.clone();
            let smtp_box_host = smtp_host_entry.clone();
            let smtp_box_user = smtp_username_entry.clone();
            let password_box = smtp_password_box.clone();
            Rc::new(move |imap: crate::account_setup::Server, smtp: crate::account_setup::Server| {
                if name.text().trim().is_empty() { name.set_text(&email.text()); }
                same.set_active(imap.host == smtp.host && imap.username == smtp.username);
                same_password.set_active(true);
                smtp_box_host.set_sensitive(!same.is_active());
                smtp_box_user.set_sensitive(!same.is_active());
                password_box.set_visible(false);
                ih.set_text(&imap.host);
                is.set_selected(security_position(imap.security));
                ip.set_value(imap.port as f64);
                iu.set_text(&imap.username);
                sh.set_text(&smtp.host);
                ss.set_selected(security_position(smtp.security));
                sp.set_value(smtp.port as f64);
                su.set_text(&smtp.username);
            })
        };
        let approved = Rc::new(RefCell::new(Vec::<String>::new()));
        let pending = Rc::new(RefCell::new(None::<String>));
        let detected_address = Rc::new(RefCell::new(String::new()));
        let detect = {
            let email = email_entry.clone();
            let password = imap_password_entry.clone();
            let button = detect_button.clone();
            let approve = approve_button.clone();
            let oab = oab_entry.clone();
            let status = setup_status.clone();
            let save_button = save_button.clone();
            let worker = worker.clone();
            let apply = apply.clone();
            let running = running.clone();
            let approved = approved.clone();
            let pending = pending.clone();
            let detected_address = detected_address.clone();
            let ready = ready.clone();
            let refresh = refresh_actions.clone();
            Rc::new(move || {
                if running.get() || !crate::recipient_entry::is_plausible_address(email.text().trim()) { return; }
                running.set(true);
                ready.set(false);
                let address = email.text().trim().to_owned();
                if *detected_address.borrow() != address {
                    approved.borrow_mut().clear();
                    pending.borrow_mut().take();
                    *detected_address.borrow_mut() = address.clone();
                }
                button.set_sensitive(false);
                approve.set_visible(false);
                save_button.set_sensitive(false);
                status.set_label("Discovering mail and Exchange settings…");
                status.set_visible(true);
                refresh();
                let (tx, rx) = async_channel::bounded(1);
                let request = address.clone();
                let secret = password.text().to_string();
                let trusted = approved.borrow().clone();
                worker.spawn(async move {
                    let result = crate::account_setup::discover(&request, &secret, trusted).await;
                    // The user's explicit Find settings action authorizes
                    // creation of the local gateway once the verified
                    // endpoint is known. Never ask for a server URL.
                    let result = match result {
                        Ok(Discovery::Exchange { ews: Some(ews), oab }) => {
                            let endpoint = ews.clone();
                            match tokio::task::spawn_blocking(move || crate::account_setup::prepare_gateway(&endpoint)).await {
                                Ok(Ok(())) => Ok(Discovery::Exchange { ews: Some(ews), oab }),
                                Ok(Err(e)) => Err(e),
                                Err(_) => Err("Gateway setup stopped".into()),
                            }
                        }
                        other => other,
                    };
                    let _ = tx.send(result).await;
                });
                let (email, approve, oab, status, apply, running, pending, password) =
                    (email.clone(), approve.clone(), oab.clone(), status.clone(), apply.clone(), running.clone(), pending.clone(), password.clone());
                let ready = ready.clone();
                let refresh = refresh.clone();
                let oauth_worker = worker.clone();
                glib::spawn_future_local(async move {
                    let result = rx.recv().await;
                    running.set(false);
                    refresh();
                    if email.text().trim() != address { status.set_label("Email changed. Find settings again."); return; }
                    match result {
                        Ok(Ok(Discovery::Mail { imap, smtp, oauth_available })) => {
                            oab.set_text("");
                            apply(imap, smtp);
                            ready.set(true);
                            refresh();
                            status.set_label(if oauth_available {
                                "Mail settings found. Use a password or an app password supported by your provider, then add the account."
                            } else {
                                "Mail settings found. Enter your password (or app password), then add the account."
                            });
                            if password.text().is_empty() { password.grab_focus(); }
                        }
                        Ok(Ok(Discovery::Exchange { ews: Some(_), oab: discovered_oab })) => {
                            oab.set_text(discovered_oab.as_deref().unwrap_or(""));
                            let server = |port| crate::account_setup::Server { host: "127.0.0.1".into(), port, security: Security::Plain, username: address.clone() };
                            apply(server(1143), server(1025));
                            ready.set(true);
                            refresh();
                            status.set_label("Exchange found. Mail, calendar and contacts are ready to connect.");
                        }
                        Ok(Ok(Discovery::PasswordRequired | Discovery::Exchange { ews: None, .. })) => {
                            status.set_label("Exchange requires authentication. Enter your password and find settings again.");
                            password.grab_focus();
                        }
                        Ok(Ok(Discovery::ApproveHost(host))) => {
                            status.set_label(&format!("Autodiscover directs your account to {host}. Trust this server only if it belongs to your organization or mail provider."));
                            *pending.borrow_mut() = Some(host);
                            approve.set_visible(true);
                        }
                        Ok(Ok(Discovery::Google)) => {
                            password.set_text("");
                            status.set_label("Google detected. Sign in to Google in Online Accounts and enable Mail. Lookout will connect automatically.");
                            oauth_worker.spawn(crate::online_accounts::open_online_accounts());
                        }
                        Ok(Ok(Discovery::OAuthRequired(provider))) => {
                            password.set_text("");
                            status.set_label(&format!("{provider} requires OAuth2. Lookout does not yet have an OAuth sign-in adapter for this provider. Use a supported Online Accounts provider if available."));
                        }
                        Ok(Ok(Discovery::Microsoft365)) => {
                            password.set_text("");
                            status.set_label("Microsoft 365 detected. Use the Microsoft 365 sign-in option in Accounts (OAuth).");
                        }
                        Ok(Err(message)) => status.set_label(&message),
                        Err(_) => status.set_label("Discovery stopped. Try again."),
                    }
                });
            })
        };
        {
            let detect = detect.clone();
            detect_button.connect_clicked(move |_| detect());
        }
        {
            let detect = detect.clone();
            email_entry.connect_activate(move |_| { detect(); });
        }
        {
            let detect = detect.clone();
            imap_password_entry.connect_activate(move |_| detect());
        }
        {
            let detect = detect.clone();
            let email = email_entry.clone();
            approve_button.connect_clicked(move |_| {
                if *detected_address.borrow() != email.text().trim() { return; }
                if let Some(host) = pending.borrow_mut().take() {
                    approved.borrow_mut().push(host);
                }
                detect();
            });
        }
    }

    let save = {
        let existing = existing.clone();
        // These three are also needed after `save` is defined below
        // (`save_button.connect_clicked`, `email_entry.connect_activate`,
        // `dialog.present()`), so `save`'s `move` closure gets its own
        // clones rather than moving the outer bindings out from under them.
        let save_button = save_button.clone();
        let email_entry = email_entry.clone();
        let dialog = dialog.clone();
        move || {
            if !save_button.is_sensitive() { return; }
            let email = email_entry.text().trim().to_string();
            let name = if name_entry.text().trim().is_empty() { email.clone() } else { name_entry.text().trim().to_string() };
            let imap_host = imap_host_entry.text().trim().to_string();
            let imap_port = imap_port_spin.value_as_int().clamp(1, 65535) as u16;
            let imap_security = selected_security(&imap_security_dropdown);
            let smtp_security = selected_security(&smtp_security_dropdown);
            let imap_username = imap_username_entry.text().trim().to_string();
            let same_server = same_server_switch.is_active();
            let smtp_host = if same_server { imap_host.clone() } else { smtp_host_entry.text().trim().to_string() };
            let smtp_port = smtp_port_spin.value_as_int().clamp(1, 65535) as u16;
            let smtp_username = if same_server {
                imap_username.clone()
            } else {
                smtp_username_entry.text().trim().to_string()
            };
            let use_same_password = same_password_switch.is_active();
            let imap_password = imap_password_entry.text().to_string();
            let smtp_password = if use_same_password {
                imap_password.clone()
            } else {
                smtp_password_entry.text().to_string()
            };

            let id = existing.as_ref().map(|a| a.id.clone()).unwrap_or_else(new_other_account_id);
            let account = OtherAccount {
                id,
                display_name: name,
                email,
                imap_host,
                imap_port,
                imap_use_tls: imap_security.is_encrypted(),
                imap_username,
                smtp_host,
                smtp_port,
                smtp_use_tls: smtp_security.is_encrypted(),
                smtp_username,
                use_same_password,
                imap_security: Some(imap_security),
                smtp_security: Some(smtp_security),
            };

            // -- validate --
            // With "same server" on, SMTP is a copy of IMAP, so only IMAP's
            // problems are worth reporting.
            let mut problems = account_problems(&account, !same_server);
            let oab_url = oab_entry.text().trim().to_string();
            if !oab_url.is_empty() && (davmail_accounts(&account).is_none() || !crate::oab_sync::valid_url(&oab_url)) {
                problems.push("OAB requires a local DavMail account and a full HTTPS oab.xml URL");
            }
            // Blank passwords are only allowed when editing (keep the stored
            // secrets); a new account must set them.
            if imap_password.is_empty() && existing.is_none() {
                problems.push("a password is required");
            }
            if !use_same_password && smtp_password.is_empty() && existing.is_none() {
                problems.push("an SMTP password is required");
            }
            if !problems.is_empty() {
                error_label.set_label(&problems.join("\n"));
                error_label.set_visible(true);
                return;
            }
            error_label.set_visible(false);

            // Keyring writes happen on the worker thread (D-Bus I/O). The
            // config mutation + save stay on the UI thread, like the
            // identities dialog, and only run once the secrets are stored -
            // a failed keyring write leaves settings.json untouched so the
            // account isn't half-configured. Blank password fields (the
            // edit-without-changing-the-password case) skip that slot's
            // write entirely, leaving the existing keyring entry untouched.
            save_button.set_sensitive(false);
            let verify = existing.is_none();
            if verify {
                error_label.set_label("Checking IMAP and SMTP authentication…");
                error_label.set_visible(true);
            }
            let keyring = keyring.clone();
            let app_config = app_config.clone();
            let dialog = dialog.clone();
            let on_saved = on_saved.clone();
            let account_for_worker = account.clone();
            let (result_tx, result_rx) = async_channel::bounded(1);
            let account_id = account.id.clone();
            let secrets: (Option<String>, Option<String>) = (
                if imap_password.is_empty() { None } else { Some(imap_password) },
                if smtp_password.is_empty() { None } else { Some(smtp_password) },
            );
            worker.spawn(async move {
                let result = async {
                    if verify {
                        let imap = secrets.0.clone().ok_or("A password is required")?;
                        let smtp = secrets.1.clone().ok_or("An SMTP password is required")?;
                        crate::account_setup::verify_credentials(&account_for_worker, imap, smtp).await?;
                    }
                    if let Some(password) = &secrets.0 {
                        keyring.store_password(&AccountId(account_for_worker.id.clone()), PROTOCOL_IMAP, password).await?;
                    }
                    if let Some(password) = &secrets.1 {
                        keyring.store_password(&AccountId(account_for_worker.id.clone()), PROTOCOL_SMTP, password).await?;
                    }
                    Ok::<_, String>(())
                }
                .await;
                let _ = result_tx.send(result).await;
            });
            // Fresh clones for this async block specifically: `save_button`
            // and `error_label` are also used synchronously above (and on
            // every future call of this `Fn` closure), so moving the
            // closure's own captured fields into the async block - rather
            // than a clone made just for it - would make `save` callable
            // only once.
            let save_button = save_button.clone();
            let error_label = error_label.clone();
            glib::spawn_future_local(async move {
                let Ok(result) = result_rx.recv().await else { return };
                match result {
                    Ok(()) => {
                        {
                            let mut config = app_config.borrow_mut();
                            config.upsert_other_account(account.clone());
                            if oab_url.is_empty() { config.oab_urls.remove(&account.id); }
                            else { config.oab_urls.insert(account.id.clone(), oab_url); }
                        }
                        crate::app_config::save(&app_config.borrow());
                        dialog.close();
                        on_saved(&account_id);
                    }
                    Err(e) => {
                        save_button.set_sensitive(true);
                        error_label.set_label(&e);
                        error_label.set_visible(true);
                    }
                }
            });
        }
    };
    let save_for_activate = {
        let save = save.clone();
        move || save()
    };
    save_button.connect_clicked(move |_| save());
    if is_edit { email_entry.connect_activate(move |_| save_for_activate()); }

    dialog.present();
    dialog
}

/// What's wrong with an account's server settings, as the dialog lists it.
/// `check_smtp` is false while the dialog's "same server" switch makes SMTP a
/// copy of IMAP. Shared with the Evolution import, which saves accounts that
/// pass without opening the dialog.
pub(crate) fn account_problems(account: &OtherAccount, check_smtp: bool) -> Vec<&'static str> {
    let mut problems = Vec::new();
    if account.display_name.trim().is_empty() {
        problems.push("a display name is required");
    }
    if !crate::recipient_entry::is_plausible_address(account.email.trim()) {
        problems.push("a valid email address is required");
    }
    if account.imap_host.trim().is_empty() {
        problems.push("an IMAP server is required");
    }
    if account.imap_username.trim().is_empty() {
        problems.push("an IMAP username is required");
    }
    if check_smtp && account.smtp_host.trim().is_empty() {
        problems.push("an SMTP server is required");
    }
    if check_smtp && account.smtp_username.trim().is_empty() {
        problems.push("an SMTP username is required");
    }
    problems
}

/// The security modes the account dialog offers, in dropdown order.
const SECURITY_CHOICES: [Security; 3] = [Security::ImplicitTls, Security::StartTls, Security::Plain];

/// The dropdown label for `security`.
fn security_label(security: Security) -> &'static str {
    match security {
        Security::ImplicitTls => "SSL/TLS",
        Security::StartTls => "STARTTLS",
        Security::Plain => "None",
    }
}

/// `security`'s position in [`SECURITY_CHOICES`].
fn security_position(security: Security) -> u32 {
    SECURITY_CHOICES.iter().position(|s| *s == security).unwrap_or(0) as u32
}

/// A security dropdown listing [`SECURITY_CHOICES`], with `initial` selected.
fn security_dropdown(initial: Security) -> gtk::DropDown {
    let labels: Vec<&str> = SECURITY_CHOICES.iter().map(|s| security_label(*s)).collect();
    let dropdown = gtk::DropDown::from_strings(&labels);
    dropdown.set_halign(gtk::Align::Start);
    dropdown.set_selected(security_position(initial));
    dropdown
}

/// The mode selected in a [`security_dropdown`].
fn selected_security(dropdown: &gtk::DropDown) -> Security {
    SECURITY_CHOICES.get(dropdown.selected() as usize).copied().unwrap_or(Security::ImplicitTls)
}

/// The port to show after switching `protocol` to `security`: the new mode's
/// standard port when `port` is one of the protocol's standard ports,
/// otherwise `port` unchanged.
fn port_for_security(protocol: Protocol, security: Security, port: u16) -> u16 {
    let is_standard = SECURITY_CHOICES.iter().any(|s| protocol.default_port(*s) == port);
    if is_standard {
        protocol.default_port(security)
    } else {
        port
    }
}

/// Keeps `spin` on the standard port of the mode chosen in `dropdown`, unless
/// the user typed a custom one (see [`port_for_security`]).
fn follow_standard_port(dropdown: &gtk::DropDown, spin: &gtk::SpinButton, protocol: Protocol) {
    let spin = spin.clone();
    dropdown.connect_selected_notify(move |dropdown| {
        let port = spin.value_as_int().clamp(1, 65535) as u16;
        let next = port_for_security(protocol, selected_security(dropdown), port);
        if next != port {
            spin.set_value(f64::from(next));
        }
    });
}

/// A fresh, stable `other:<uuid>` id for a new manual account.
pub(crate) fn new_other_account_id() -> String {
    format!("{OTHER_ACCOUNT_ID_PREFIX}{}", uuid::Uuid::new_v4())
}

/// A right-aligned field label for the two-column form grid.
pub(crate) fn field_label(text: &str) -> gtk::Label {
    let label = gtk::Label::builder().label(text).halign(gtk::Align::End).build();
    crate::privacy::mark_ui(&label);
    label
}

/// A small "Port" caption for the grid's port columns.
pub(crate) fn port_label(text: &str) -> gtk::Label {
    let label = gtk::Label::builder().label(text).css_classes(["dim-label"]).build();
    crate::privacy::mark_ui(&label);
    label
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory keyring for tests: a map of `(account, protocol)` to the
    /// stored password, behind a mutex for the `Send + Sync` trait bound.
    #[derive(Default)]
    struct FakeKeyring {
        secrets: Mutex<HashMap<(String, String), String>>,
    }

    #[async_trait]
    impl KeyringStore for FakeKeyring {
        async fn load_password(&self, account_id: &AccountId, protocol: &str) -> Result<String, String> {
            self.secrets
                .lock()
                .unwrap()
                .get(&(account_id.0.clone(), protocol.to_string()))
                .cloned()
                .ok_or_else(|| "missing".to_string())
        }

        async fn store_password(&self, account_id: &AccountId, protocol: &str, password: &str) -> Result<(), String> {
            self.secrets.lock().unwrap().insert((account_id.0.clone(), protocol.to_string()), password.to_string());
            Ok(())
        }

        async fn delete_account(&self, account_id: &AccountId) -> Result<(), String> {
            self.secrets.lock().unwrap().retain(|(id, _), _| id != &account_id.0);
            Ok(())
        }
    }

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(fut)
    }

    #[test]
    fn davmail_endpoints_require_plain_local_mail_and_keep_account_identity() {
        let mut account = OtherAccount {
            id: "other:12345678-1234-4234-8234-123456789abc".into(),
            display_name: "Example".into(),
            email: "alice@example.test".into(),
            imap_host: "localhost".into(),
            imap_port: 1143,
            imap_use_tls: false,
            imap_username: "alice".into(),
            smtp_host: "127.0.0.1".into(),
            smtp_port: 1025,
            smtp_use_tls: false,
            smtp_username: "alice".into(),
            use_same_password: true,
            imap_security: Some(Security::Plain),
            smtp_security: Some(Security::Plain),
        };
        let (calendar, contacts) = davmail_accounts(&account).unwrap();
        assert_eq!(calendar.account_id.0, account.id);
        assert_eq!(contacts.account_id, calendar.account_id);
        assert_eq!(calendar.identity, "alice");
        assert_eq!(calendar.uri, "http://127.0.0.1:1080/users/alice@example.test/calendar/");
        assert_eq!(contacts.uri, "http://127.0.0.1:1080/users/alice@example.test/contacts/");
        account.imap_host = "remote.example.test".into();
        assert!(davmail_accounts(&account).is_none());
        account.imap_host = "localhost".into();
        account.smtp_security = Some(Security::StartTls);
        assert!(davmail_accounts(&account).is_none());
    }

    #[test]
    fn davmail_calendar_uses_the_existing_imap_secret() {
        use lookout_dav::session::CalendarCredentialProvider;
        let keyring = Arc::new(FakeKeyring::default());
        let id = AccountId("other:test".into());
        block_on(keyring.store_password(&id, PROTOCOL_IMAP, "imap-secret")).unwrap();
        let provider = OtherCredentialProvider::new(id.clone(), keyring.clone());
        block_on(async {
            assert!(matches!(provider.calendar_credential().await.unwrap(), lookout_dav::Credential::Password(p) if p == "imap-secret"));
            keyring.delete_account(&id).await.unwrap();
            assert!(provider.calendar_credential().await.is_err());
        });
    }

    #[test]
    fn provider_reads_the_matching_protocol_slots() {
        let keyring = Arc::new(FakeKeyring::default());
        let account_id = AccountId(format!("{OTHER_ACCOUNT_ID_PREFIX}t"));
        block_on(keyring.store_password(&account_id, PROTOCOL_IMAP, "imap-secret")).unwrap();
        block_on(keyring.store_password(&account_id, PROTOCOL_SMTP, "smtp-secret")).unwrap();

        let provider = OtherCredentialProvider::new(account_id.clone(), keyring.clone());
        block_on(async {
            match provider.imap_credential().await.unwrap() {
                Credential::Password(p) => assert_eq!(p, "imap-secret"),
                _ => panic!("expected a password credential"),
            }
            match provider.smtp_credential().await.unwrap() {
                Credential::Password(p) => assert_eq!(p, "smtp-secret"),
                _ => panic!("expected a password credential"),
            }
            // The slots are independent.
            assert!(provider.imap_credential().await.is_ok());
            keyring.delete_account(&account_id).await.unwrap();
            assert!(provider.imap_credential().await.is_err());
            assert!(provider.smtp_credential().await.is_err());
        });
    }

    #[test]
    fn provider_uses_distinct_passwords_when_stored_so() {
        let keyring = Arc::new(FakeKeyring::default());
        let account_id = AccountId(format!("{OTHER_ACCOUNT_ID_PREFIX}t2"));
        block_on(keyring.store_password(&account_id, PROTOCOL_IMAP, "a")).unwrap();
        block_on(keyring.store_password(&account_id, PROTOCOL_SMTP, "b")).unwrap();
        let provider = OtherCredentialProvider::new(account_id, keyring);
        block_on(async {
            match provider.imap_credential().await.unwrap() {
                Credential::Password(p) => assert_eq!(p, "a"),
                _ => panic!(),
            }
            match provider.smtp_credential().await.unwrap() {
                Credential::Password(p) => assert_eq!(p, "b"),
                _ => panic!(),
            }
        });
    }

    #[test]
    fn switching_security_moves_only_a_standard_port() {
        assert_eq!(port_for_security(Protocol::Imap, Security::StartTls, 993), 143);
        assert_eq!(port_for_security(Protocol::Imap, Security::ImplicitTls, 143), 993);
        assert_eq!(port_for_security(Protocol::Imap, Security::Plain, 993), 143);
        assert_eq!(port_for_security(Protocol::Smtp, Security::ImplicitTls, 587), 465);
        assert_eq!(port_for_security(Protocol::Smtp, Security::StartTls, 465), 587);
        assert_eq!(port_for_security(Protocol::Imap, Security::StartTls, 1993), 1993);
        assert_eq!(port_for_security(Protocol::Smtp, Security::ImplicitTls, 2525), 2525);
        for security in SECURITY_CHOICES {
            assert_eq!(SECURITY_CHOICES[security_position(security) as usize], security);
        }
    }

    #[test]
    fn keyring_error_messages_are_human_readable() {
        assert!(keyring_error(secret_service::Error::Unavailable).contains("keyring"));
        assert!(keyring_error(secret_service::Error::NoResult).contains("collection"));
        assert!(!keyring_error(secret_service::Error::Locked).is_empty());
    }

    #[test]
    fn ldap_bind_password_uses_its_own_slot_keyed_by_the_directory_id() {
        use crate::app_config::LDAP_DIRECTORY_ID_PREFIX;

        let keyring = Arc::new(FakeKeyring::default());
        let directory_id = AccountId(format!("{LDAP_DIRECTORY_ID_PREFIX}1234"));
        block_on(keyring.store_password(&directory_id, PROTOCOL_LDAP, "bind-secret")).unwrap();

        block_on(async {
            assert_eq!(keyring.load_password(&directory_id, PROTOCOL_LDAP).await.unwrap(), "bind-secret");
            // The slot is independent of the mail protocols a same-named
            // account would use.
            assert!(keyring.load_password(&directory_id, PROTOCOL_IMAP).await.is_err());
            // Removing the directory drops the bind password with the same
            // call the other-account removal uses.
            keyring.delete_account(&directory_id).await.unwrap();
            assert!(keyring.load_password(&directory_id, PROTOCOL_LDAP).await.is_err());
        });
    }
}
