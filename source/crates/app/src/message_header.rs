/// Copyright (C) <2026>  <Gavin Graham & Contributors>
/// Software released under the GPL3 license
use adw::prelude::*;
use lookout_core::EmailSummary;

use crate::util::action_button;

pub const AVATAR_COLOR_CLASSES: [&str; 6] = ["avatar-color-0", "avatar-color-1", "avatar-color-2", "avatar-color-3", "avatar-color-4", "avatar-color-5"];

/// Shared message header for the reading pane and standalone reader.
/// One local Reply / Reply All / Forward row precedes the body.
/// The global mail ribbon remains independent; there is no footer action row.
#[derive(Clone)]
pub struct MessageHeader {
    pub subject_bar: gtk::Box,
    /// "Back to conversation", shown above the subject while a message of
    /// the conversation view is open on its own ("Show details", item 1.7);
    /// hidden otherwise. Wired in `window.rs`.
    pub back_button: gtk::Button,
    pub widget: gtk::Box,
    subject_label: gtk::Label,
    /// The sender avatar/name/address labels. `pub(crate)` so `window.rs` can
    /// attach the profile-card trigger (Phase 4.2 / UX-67) to the avatar and
    /// name after the header is built.
    pub(crate) avatar_label: gtk::Label,
    pub(crate) sender_name_label: gtk::Label,
    sender_email_label: gtk::Label,
    to_label: gtk::Label,
    cc_label: gtk::Label,
    bcc_label: gtk::Label,
    date_label: gtk::Label,
    pub reply_button: gtk::Button,
    pub reply_all_button: gtk::Button,
    pub forward_button: gtk::Button,
    /// The "View contact" button: looks up the sender in the connected
    /// contacts accounts - opening the contact editor for the found card, or
    /// a prefilled create dialog - wired up in `window.rs`, which owns the
    /// contact state the lookup needs.
    pub contact_button: gtk::Button,
    /// The "Switch message theme" toggle: when active, the message body's
    /// own background colour is removed - and its colours inverted - so the
    /// content reads against the app theme's background instead. A per-email
    /// override - the selection handler resets the backing `UiState` flag to
    /// the Config → Appearance "Dark message theme" default on every
    /// navigation and `render_body` syncs this button from it, so the next
    /// message opens in that default.
    pub theme_button: gtk::ToggleButton,
}

/// A flat button with an icon + text label, via `adw::ButtonContent` - used
/// for the Reply/Reply All/Forward cluster so they read as labelled actions
/// rather than bare icon chrome.
/// A disabled placeholder button for a control that isn't wired up yet - same
/// convention as the top command toolbar's `more_button`. The tooltip names
/// what it will do so the disabled state reads as "not yet" rather than
/// "broken".
fn placeholder_button(icon: &str, tooltip: &str) -> gtk::Button {
    let button = gtk::Button::builder().icon_name(icon).css_classes(["flat"]).build();
    button.set_tooltip_text(Some(tooltip));
    button.set_sensitive(false);
    button
}

pub fn build() -> MessageHeader {
    let subject_label = gtk::Label::builder().xalign(0.0).wrap(true).css_classes(["message-header-subject"]).build();
    let subject_bar = gtk::Box::builder().orientation(gtk::Orientation::Vertical).css_classes(["message-subject-bar"]).build();
    subject_bar.set_widget_name("subject-bar");
    let back_button = gtk::Button::builder()
        .child(&adw::ButtonContent::builder().icon_name("go-previous-symbolic").label("Back to conversation").build())
        .css_classes(["flat"])
        .halign(gtk::Align::Start)
        .visible(false)
        .build();
    subject_bar.append(&back_button);
    subject_bar.append(&subject_label);
    crate::privacy::mark(&subject_label);

    let avatar_label = gtk::Label::builder()
        .css_classes(["avatar-circle"])
        .width_request(40)
        .height_request(40)
        .halign(gtk::Align::Center)
        .valign(gtk::Align::Center)
        .build();
    // Sender initials are derived from the sender's name/address: privacy mode
    // blurs them.
    crate::privacy::mark(&avatar_label);

    let sender_name_label = gtk::Label::builder().xalign(0.0).css_classes(["heading"]).ellipsize(gtk::pango::EllipsizeMode::End).build();
    let sender_email_label = gtk::Label::builder()
        .xalign(0.0)
        .css_classes(["message-header-meta"])
        .ellipsize(gtk::pango::EllipsizeMode::End)
        .build();
    // The reading pane's From name and address.
    crate::privacy::mark(&sender_name_label);
    crate::privacy::mark(&sender_email_label);
    let sender_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(2)
        .hexpand(true)
        .valign(gtk::Align::Center)
        .build();
    sender_box.append(&sender_name_label);
    sender_box.append(&sender_email_label);

    let reply_button = action_button("mail-reply-sender-symbolic", "Reply");
    reply_button.set_tooltip_text(Some("Reply"));
    let reply_all_button = action_button("mail-reply-all-symbolic", "Reply all");
    reply_all_button.set_tooltip_text(Some("Reply All"));
    let forward_button = action_button("mail-forward-symbolic", "Forward");
    forward_button.set_tooltip_text(Some("Forward"));

    let theme_button = gtk::ToggleButton::builder()
        // A moon by default - the button is off - swapped for a sun while the
        // override is on, by the toggle handler in `window.rs`. The moon list
        // trails off into the sun so an icon theme with no moon glyph still
        // gets something real rather than a missing-image box.
        .icon_name(crate::window::themed_icon_name(&[
            "weather-clear-night-symbolic",
            "night-light-symbolic",
            "weather-clear-symbolic",
        ]))
        .css_classes(["flat"])
        // The tooltip names what the button *does* when clicked, so it flips
        // with the toggle's state: off reads "View in Dark Mode" (clicking
        // strips the email's background and inverts the text), on reads
        // "View in Light Mode". The toggle handler in `window.rs` keeps it
        // in sync, including when `render_body` resets the button off for
        // the next message.
        .tooltip_text("View in Dark Mode")
        .build();
    let contact_button = gtk::Button::builder()
        .icon_name(crate::window::themed_icon_name(&[
            "avatar-default-symbolic",
            "contact-new-symbolic",
            "system-users-symbolic",
        ]))
        .css_classes(["flat"])
        .tooltip_text("View contact")
        .build();
    let header_more_button = placeholder_button("view-more-symbolic", "More (coming soon)");

    let sender_row = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(8).build();
    sender_row.append(&avatar_label);
    sender_row.append(&sender_box);
    sender_row.append(&contact_button);
    let commands = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(4).css_classes(["message-command-row"]).build();
    for button in [&reply_button, &reply_all_button, &forward_button] {
        button.remove_css_class("flat");
        button.add_css_class("message-command");
        commands.append(button);
    }
    sender_row.append(&theme_button);
    commands.set_halign(gtk::Align::Start);
    // Do not show a dead More button in every opened message.
    header_more_button.set_visible(false);

    let recipient_label = || {
        let label = gtk::Label::builder().xalign(0.0).hexpand(true)
            .wrap(true).wrap_mode(gtk::pango::WrapMode::WordChar)
            .selectable(true).css_classes(["message-header-meta"]).build();
        crate::privacy::mark(&label);
        label
    };
    let to_label = recipient_label();
    let cc_label = recipient_label();
    let bcc_label = recipient_label();
    let date_label = gtk::Label::builder().xalign(0.0).css_classes(["message-header-meta"]).build();
    let meta_row = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(3).build();
    for label in [&to_label, &cc_label, &bcc_label, &date_label] { meta_row.append(label); }

    let widget = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(4)
        .margin_top(12)
        .margin_bottom(8)
        .margin_start(12)
        .margin_end(12)
        .build();
    widget.append(&sender_row);
    widget.append(&meta_row);
    widget.append(&commands);

    MessageHeader {
        subject_bar,
        back_button,
        widget,
        subject_label,
        avatar_label,
        sender_name_label,
        sender_email_label,
        to_label,
        cc_label,
        bcc_label,
        date_label,
        reply_button,
        reply_all_button,
        forward_button,
        contact_button,
        theme_button,
    }
}

impl MessageHeader {
    pub fn update(&self, summary: &EmailSummary) {
        self.subject_label.set_label(summary.subject.as_deref().unwrap_or("(no subject)"));

        match summary.from.first() {
            Some(sender) => {
                self.sender_name_label.set_label(sender.display_label());
                let has_distinct_name = sender.name.as_deref().is_some_and(|n| !n.trim().is_empty());
                self.sender_email_label.set_label(&format!("<{}>", sender.address));
                self.sender_email_label.set_visible(has_distinct_name);

                self.avatar_label.set_label(&initials(sender.name.as_deref(), &sender.address));
                for class in AVATAR_COLOR_CLASSES {
                    self.avatar_label.remove_css_class(class);
                }
                self.avatar_label.add_css_class(avatar_color_class(&sender.address));
            }
            None => {
                self.sender_name_label.set_label("Unknown sender");
                self.sender_email_label.set_visible(false);
                self.avatar_label.set_label("?");
            }
        }

        set_recipient_line(&self.to_label, "To", &summary.to);
        set_recipient_line(&self.cc_label, "Cc", &summary.cc);
        self.bcc_label.set_label("");
        self.bcc_label.set_visible(false);

        self.date_label
            .set_label(&summary.date.with_timezone(&chrono::Local).format("%a %d/%m/%Y %I:%M %p").to_string());
    }

    /// Bcc is deliberately not in EmailSummary: display it only if the
    /// opened message actually contains a Bcc header, never infer it.
    pub fn update_body_headers(&self, headers: &[(String, String)]) {
        let raw = headers.iter().filter(|(name, _)| name.eq_ignore_ascii_case("bcc"))
            .map(|(_, value)| value.trim()).filter(|value| !value.is_empty())
            .collect::<Vec<_>>().join(", ");
        self.bcc_label.set_label(&format!("Bcc: {raw}"));
        self.bcc_label.set_visible(!raw.is_empty());
    }
}

fn set_recipient_line(label: &gtk::Label, prefix: &str, addresses: &[lookout_core::EmailAddress]) {
    let text = addresses.iter().map(|a| a.display_label()).collect::<Vec<_>>().join(", ");
    label.set_label(&format!("{prefix}: {text}"));
    label.set_visible(!addresses.is_empty());
}

/// First+last initials for a multi-word name ("Microsoft Security" -> "MS",
/// "John Jacob Astor" -> "JA"), else the first character of whatever single
/// word/address is given.
pub fn initials(name: Option<&str>, address: &str) -> String {
    let source = name.filter(|n| !n.trim().is_empty()).unwrap_or(address);
    let words: Vec<&str> = source.split_whitespace().collect();
    match (words.first(), words.last()) {
        (Some(first), Some(last)) if words.len() > 1 => {
            let a = first.chars().next().unwrap_or('?');
            let b = last.chars().next().unwrap_or('?');
            format!("{a}{b}").to_uppercase()
        }
        (Some(only), _) => only.chars().take(1).collect::<String>().to_uppercase(),
        _ => "?".to_string(),
    }
}

/// Picks a deterministic avatar background color class from `seed` (the
/// sender's address), so the same sender always gets the same color - a
/// fixed palette of CSS classes registered once (see
/// `data/styles/message-header.css`) rather than per-instance inline styling.
pub fn avatar_color_class(seed: &str) -> &'static str {
    let hash = seed.bytes().fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
    AVATAR_COLOR_CLASSES[(hash as usize) % AVATAR_COLOR_CLASSES.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_commands_are_attached_to_the_header() {
        if !crate::gtk_test::gtk_ready() { return; }
        let header = build();
        for button in [&header.reply_button, &header.reply_all_button, &header.forward_button] {
            let row = button.parent().expect("local message action row");
            assert_eq!(row.parent().unwrap(), header.widget.clone().upcast::<gtk::Widget>());
            assert!(button.is_visible());
        }
    }

    #[test]
    fn initials_uses_first_and_last_word_of_a_multi_word_name() {
        assert_eq!(initials(Some("Microsoft Security"), "msft@example.com"), "MS");
        assert_eq!(initials(Some("Ada Lovelace"), "ada@example.com"), "AL");
        assert_eq!(initials(Some("John Jacob Astor"), "jja@example.com"), "JA");
    }

    #[test]
    fn initials_uses_first_word_last_letter_of_a_single_word_name() {
        assert_eq!(initials(None, "ada@example.com"), "A");
        assert_eq!(initials(Some(""), "ada@example.com"), "A");
        assert_eq!(initials(Some("Ada"), "ada@example.com"), "A");
    }

    #[test]
    fn avatar_color_class_is_deterministic_per_seed() {
        let a = avatar_color_class("ada@example.com");
        let b = avatar_color_class("ada@example.com");
        assert_eq!(a, b);
        assert!(AVATAR_COLOR_CLASSES.contains(&a));
    }
}
