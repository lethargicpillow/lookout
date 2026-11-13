//! The profile card (Phase 4.2 / P-10, UX-67): an in-window overlay showing a person's
//! contact details, their recent mail, upcoming shared events and a small set
//! of actions, opened by hovering or clicking a person reference - the
//! reading-pane sender, a conversation card's sender, an event editor's
//! attendee chip, an invitation card's organizer, or a People row - and by
//! hovering (never clicking) a message-list row's avatar, or its sender name
//! when the row shows no avatar.
//!
//! One reusable component serves every surface so placement, wording and
//! behaviour stay identical everywhere (§6.1 rule 4): `attach_person_trigger`
//! for explicit references (click or hover), and [`PersonHover`] for
//! message-list rows, whose clicks belong to message selection.
//! The card itself is data-in/widget-out: the host window supplies the
//! [`ProfileCardActions`] closures that open composers, events and contact
//! dialogs, so this module never reaches into session or window internals.

/// Copyright (C) <2026>  <Gavin Graham & Contributors>
/// Software released under the GPL3 license
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use adw::prelude::*;
use chrono::{Duration, NaiveDateTime};
use gtk::glib;
use lookout_core::{AccountId, EmailAddress, EmailSummary, EventOccurrence, VCard};

use crate::util::action_button;
use crate::window::UiState;
use crate::worker::Worker;

/// How long the pointer must rest on a person reference before the hover card
/// opens (a shorter delay than a tooltip, matching Outlook's quick reveal).
const HOVER_DELAY_MS: u64 = 350;
/// How many recent messages the card lists.
const RECENT_MAIL_LIMIT: usize = 5;
/// How many upcoming shared events the card lists.
const UPCOMING_EVENTS_LIMIT: usize = 3;
/// How far ahead the events section looks.
const EVENT_HORIZON_DAYS: i64 = 90;

/// A lazily-resolved person reference: the address plus the account it came
/// from (which the composer should send from, when known).
pub type PersonResolver = Rc<dyn Fn() -> Option<(EmailAddress, Option<AccountId>)>>;
/// A late-bound provider of the window's card context: the message-list rows
/// are built before the context exists, so they resolve it at click time.
pub type ContextProvider = Rc<dyn Fn() -> Option<Rc<ProfileCardContext>>>;
/// A card action that acts on one person.
pub type PersonActionFn = Rc<dyn Fn(&EmailAddress)>;
/// "Send email": the person plus the account to send from.
pub type SendEmailFn = Rc<dyn Fn(&EmailAddress, Option<AccountId>)>;
/// "Open message": the message to open.
pub type OpenMessageFn = Rc<dyn Fn(&EmailSummary)>;
/// "Open event": the occurrence to open.
pub type OpenEventFn = Rc<dyn Fn(&EventOccurrence)>;
/// The occurrences a person organizes or attends.
pub type EventsForPersonFn = Rc<dyn Fn(&str) -> Vec<EventOccurrence>>;

/// The actions a card offers, built by the host window (which owns the
/// reading pane, sessions and dialogs). Every closure takes the person the
/// card is about, so one [`ProfileCardActions`] serves every trigger.
#[derive(Clone)]
pub struct ProfileCardActions {
    /// Open a blank composer addressed to the person, from the given account
    /// (or the default account when `None`).
    pub send_email: SendEmailFn,
    /// Open a new event with the person as an attendee.
    pub schedule_meeting: PersonActionFn,
    /// Open the blank "new contact" editor prefilled with the person.
    pub add_contact: PersonActionFn,
    /// Open the existing contact in the editor.
    pub edit_contact: PersonActionFn,
    /// Open a recent message in the reading pane.
    pub open_message: OpenMessageFn,
    /// Open an upcoming shared event in the event editor.
    pub open_event: OpenEventFn,
    /// Every occurrence (from any calendar) that the given address organizes
    /// or attends. The card filters these to the upcoming ones itself.
    pub events_for_person: EventsForPersonFn,
}

/// Everything the card needs to render and act, assembled once per window.
#[derive(Clone)]
pub struct ProfileCardContext {
    pub state: Rc<RefCell<UiState>>,
    pub worker: Rc<Worker>,
    pub actions: ProfileCardActions,
}

/// Whether an occurrence involves `address` as organizer or attendee.
fn occurrence_involves(occ: &EventOccurrence, address: &str) -> bool {
    occ.organizer.as_ref().is_some_and(|a| a.address.eq_ignore_ascii_case(address)) || occ.attendees.iter().any(|a| a.address.address.eq_ignore_ascii_case(address))
}

/// The upcoming occurrences `address` is part of, sorted by start and capped
/// at `limit`. Pure so it can be unit-tested without a GTK loop; `now` and
/// the occurrence starts are compared as local wall-clock times in the
/// calendar's display zone, where an all-day event starts at 00:00.
pub fn shared_upcoming_events(occurrences: &[EventOccurrence], address: &str, now: NaiveDateTime, horizon: Duration, limit: usize) -> Vec<EventOccurrence> {
    let zone = crate::calendar_tz::display_zone();
    let horizon_end = now + horizon;
    let mut upcoming: Vec<EventOccurrence> = occurrences
        .iter()
        .filter(|occ| occurrence_involves(occ, address))
        .filter(|occ| {
            let start = zone.occurrence_to_local(occ.start, occ.all_day);
            start >= now && start <= horizon_end
        })
        .cloned()
        .collect();
    upcoming.sort_by_key(|occ| occ.start);
    upcoming.truncate(limit);
    upcoming
}

/// How long the pointer can travel between a trigger and its card.
const HOVER_CLOSE_DELAY_MS: u64 = 150;
pub type HoverEnabled = Rc<dyn Fn() -> bool>;
type CardSlot = Rc<RefCell<Option<gtk::Widget>>>;
type TimerSlot = Rc<RefCell<Option<glib::SourceId>>>;

/// At most one contact card at a time. The card is an ordinary child of
/// the owning window's overlay: no GtkPopover, GdkPopup, native window,
/// keyboard grab or independent stacking order.
struct CardPlacement {
    panel: glib::WeakRef<gtk::Widget>,
    anchor: glib::WeakRef<gtk::Widget>,
    point: Option<(f64, f64)>,
}

thread_local! {
    static CARD_PLACEMENT: RefCell<Option<CardPlacement>> = const { RefCell::new(None) };
}

fn current_panel() -> Option<gtk::Widget> {
    CARD_PLACEMENT.with(|slot| slot.borrow().as_ref().and_then(|card| card.panel.upgrade()))
}

fn close_panel(panel: &gtk::Widget) {
    CARD_PLACEMENT.with(|slot| {
        let matches = slot.borrow().as_ref().and_then(|card| card.panel.upgrade())
            .is_some_and(|current| current == *panel);
        if matches { slot.borrow_mut().take(); }
    });
    panel.set_visible(false);
    if let Some(host) = panel.parent().and_downcast::<gtk::Overlay>() {
        host.remove_overlay(panel);
    }
}

fn close_current_card() {
    if let Some(panel) = current_panel() { close_panel(&panel); }
}

pub(crate) fn dismiss_for_window(window: &gtk::Window) {
    if let Some(panel) = current_panel() {
        if crate::window_input::owner_window(&panel).as_ref() == Some(window) {
            close_panel(&panel);
        }
    }
}

fn dismiss_slot(active: &CardSlot, timer: &TimerSlot) {
    cancel_timer(timer);
    let previous = active.borrow_mut().take();
    if let Some(previous) = previous { close_panel(&previous); }
}

/// Installs a non-measuring, clipped card layer on a window's existing
/// overlay. Other overlay children keep their existing allocation rules.
pub(crate) fn prepare_host(host: &gtk::Overlay) {
    if host.has_css_class("profile-card-host") { return; }
    host.add_css_class("profile-card-host");
    host.connect_get_child_position(|host, child| {
        if !child.has_css_class("profile-card-panel") { return None; }
        let (anchor, point) = CARD_PLACEMENT.with(|slot| {
            let slot = slot.borrow();
            let placement = slot.as_ref()?;
            if placement.panel.upgrade().as_ref() != Some(child) { return None; }
            Some((placement.anchor.upgrade()?, placement.point))
        })?;
        let bounds = anchor.compute_bounds(host)?;
        let width = host.width().max(1);
        let height = host.height().max(1);
        let w = child.measure(gtk::Orientation::Horizontal, -1).1
            .clamp(320, 520).min(width).max(1);
        let h = child.measure(gtk::Orientation::Vertical, w).1
            .clamp(1, 560).min(height).max(1);
        let (x, top, bottom) = match point {
            Some((x, y)) => {
                let px = bounds.x() as f64 + x;
                let py = bounds.y() as f64 + y;
                (px as i32, py as i32, py as i32)
            }
            None => (bounds.x().floor() as i32, bounds.y().floor() as i32,
                (bounds.y() + bounds.height()).ceil() as i32),
        };
        let x = x.clamp(0, width - w);
        // No gap: the pointer can enter the card before the hover-close
        // grace expires, even on a small display.
        let y = if bottom + h <= height { bottom } else { top - h };
        Some(gtk::gdk::Rectangle::new(x, y.clamp(0, height - h), w, h))
    });

    // Outside presses dismiss without claiming the event: clicking another
    // message still selects it, and a press on a card action reaches it.
    let clicks = gtk::GestureClick::new();
    clicks.set_button(0);
    clicks.set_propagation_phase(gtk::PropagationPhase::Capture);
    clicks.connect_pressed(|gesture, _, x, y| {
        let Some(host) = gesture.widget().and_downcast::<gtk::Overlay>() else { return };
        let Some(panel) = current_panel() else { return };
        if panel.parent().as_ref() != Some(host.upcast_ref::<gtk::Widget>()) { return; }
        let inside = panel.compute_bounds(&host).is_some_and(|r|
            x >= r.x() as f64 && y >= r.y() as f64
            && x < (r.x() + r.width()) as f64 && y < (r.y() + r.height()) as f64);
        if !inside { close_panel(&panel); }
    });
    host.add_controller(clicks);
    host.connect_unmap(|host| {
        if let Some(panel) = current_panel() {
            if panel.parent().as_ref() == Some(host.upcast_ref::<gtk::Widget>()) {
                close_panel(&panel);
            }
        }
    });
}

fn find_host(anchor: &gtk::Widget) -> Option<gtk::Overlay> {
    let mut current = Some(anchor.clone());
    while let Some(widget) = current {
        if widget.has_css_class("profile-card-host") {
            return widget.downcast::<gtk::Overlay>().ok();
        }
        current = widget.parent();
    }
    None
}

/// A label can occupy the entire available column while only a small
/// portion contains the sender's name. Test the visible Pango ink bounds,
/// not the allocation. Avatar triggers intentionally use their full circle.
fn trigger_contains(widget: &gtk::Widget, x: f64, y: f64) -> bool {
    if x < 0.0 || y < 0.0 || x >= widget.width() as f64 || y >= widget.height() as f64 {
        return false;
    }
    let Some(label) = widget.downcast_ref::<gtk::Label>() else { return true };
    if label.has_css_class("avatar-circle") { return true; }
    let (ink, _) = label.layout().pixel_extents();
    let (ox, oy) = label.layout_offsets();
    let left = (ox + ink.x() - 3) as f64;
    let right = (ox + ink.x() + ink.width() + 3) as f64;
    let top = (oy + ink.y() - 3) as f64;
    let bottom = (oy + ink.y() + ink.height() + 3) as f64;
    ink.width() > 0 && ink.height() > 0 && x >= left && x < right && y >= top && y < bottom
}

/// Track entry into the actual contact hit area even if the pointer was
/// already inside the label's wider allocation.
fn track_trigger(widget: &gtk::Widget, enter: Rc<dyn Fn()>, leave: Rc<dyn Fn()>) {
    let inside = Rc::new(Cell::new(false));
    let motion = gtk::EventControllerMotion::new();
    let update: Rc<dyn Fn(f64, f64)> = {
        let weak = widget.downgrade();
        let inside = inside.clone();
        let leave = leave.clone();
        Rc::new(move |x, y| {
            let hit = weak.upgrade().is_some_and(|widget| trigger_contains(&widget, x, y));
            if inside.replace(hit) != hit {
                if hit { enter(); } else { leave(); }
            }
        })
    };
    {
        let update = update.clone();
        motion.connect_enter(move |_, x, y| update(x, y));
    }
    motion.connect_motion(move |_, x, y| update(x, y));
    motion.connect_leave(move |_| {
        if inside.replace(false) { leave(); }
    });
    widget.add_controller(motion);
}

fn close_after_leave(active: &CardSlot, timer: &TimerSlot) {
    if active.borrow().is_some() {
        let active = active.clone();
        let timer_for_close = timer.clone();
        arm_timer(timer, std::time::Duration::from_millis(HOVER_CLOSE_DELAY_MS),
            move || dismiss_slot(&active, &timer_for_close));
    } else {
        cancel_timer(timer);
    }
}

fn attach_card_motion(panel: &gtk::Widget, active: &CardSlot, timer: &TimerSlot) {
    let motion = gtk::EventControllerMotion::new();
    {
        let timer = timer.clone();
        motion.connect_enter(move |_, _, _| cancel_timer(&timer));
    }
    {
        let active = active.clone();
        let timer = timer.clone();
        motion.connect_leave(move |_| close_after_leave(&active, &timer));
    }
    panel.add_controller(motion);
}

/// Explicit contact references (header sender, attendee chip): a click or a
/// short hover on the actual name/avatar opens the shared non-native card.
pub fn attach_person_trigger<W: IsA<gtk::Widget>>(context: ContextProvider, widget: &W, claim_press: bool, resolve: PersonResolver) {
    let widget = widget.clone().upcast::<gtk::Widget>();
    let active: CardSlot = Rc::new(RefCell::new(None));
    let timer: TimerSlot = Rc::new(RefCell::new(None));
    let click = gtk::GestureClick::new();
    click.set_button(gtk::gdk::BUTTON_PRIMARY);
    {
        let context = context.clone();
        let weak = widget.downgrade();
        let resolve = resolve.clone();
        let active = active.clone();
        let timer = timer.clone();
        click.connect_pressed(move |gesture, _, x, y| {
            let Some(widget) = weak.upgrade() else { return };
            if !trigger_contains(&widget, x, y) || !crate::window_input::accepts_input(&widget) { return; }
            if claim_press { gesture.set_state(gtk::EventSequenceState::Claimed); }
            cancel_timer(&timer);
            if let Some(panel) = show_card(&context, &widget, &resolve, &active) {
                attach_card_motion(&panel, &active, &timer);
            }
        });
    }
    widget.add_controller(click);

    let enter: Rc<dyn Fn()> = {
        let context = context.clone();
        let weak = widget.downgrade();
        let resolve = resolve.clone();
        let active = active.clone();
        let timer = timer.clone();
        Rc::new(move || {
            cancel_timer(&timer);
            if active.borrow().is_some() { return; }
            let (context, weak, resolve, active, timer_for_open) =
                (context.clone(), weak.clone(), resolve.clone(), active.clone(), timer.clone());
            arm_timer(&timer, std::time::Duration::from_millis(HOVER_DELAY_MS), move || {
                let Some(widget) = weak.upgrade() else { return };
                if let Some(panel) = show_card(&context, &widget, &resolve, &active) {
                    attach_card_motion(&panel, &active, &timer_for_open);
                }
            });
        })
    };
    let leave: Rc<dyn Fn()> = {
        let active = active.clone();
        let timer = timer.clone();
        Rc::new(move || close_after_leave(&active, &timer))
    };
    track_trigger(&widget, enter, leave);
    widget.connect_unmap(move |_| dismiss_slot(&active, &timer));
}

/// Hover-only contact card for a message row. The row keeps its own click
/// and keyboard selection; the card is a sibling at the window level.
#[derive(Clone)]
pub struct PersonHover {
    context: ContextProvider,
    resolve: PersonResolver,
    active: CardSlot,
    timer: TimerSlot,
}

impl PersonHover {
    pub fn new<R: IsA<gtk::Widget>>(context: ContextProvider, row: &R, resolve: PersonResolver) -> Self {
        let hover = Self {
            context, resolve,
            active: Rc::new(RefCell::new(None)),
            timer: Rc::new(RefCell::new(None)),
        };
        let presses = gtk::EventControllerLegacy::new();
        presses.set_propagation_phase(gtk::PropagationPhase::Capture);
        {
            let hover = hover.clone();
            presses.connect_event(move |_, event| {
                if event.event_type() == gtk::gdk::EventType::ButtonPress { hover.close(); }
                glib::Propagation::Proceed
            });
        }
        row.add_controller(presses);
        hover
    }

    pub fn add_trigger<W: IsA<gtk::Widget>>(&self, widget: &W, enabled: HoverEnabled) {
        let widget = widget.clone().upcast::<gtk::Widget>();
        let enter: Rc<dyn Fn()> = {
            let hover = self.clone();
            let weak = widget.downgrade();
            Rc::new(move || {
                cancel_timer(&hover.timer);
                if hover.active.borrow().is_some() || !enabled() { return; }
                let opener = hover.clone();
                let weak = weak.clone();
                arm_timer(&hover.timer, std::time::Duration::from_millis(HOVER_DELAY_MS), move || {
                    if let Some(widget) = weak.upgrade() { opener.open(&widget); }
                });
            })
        };
        let leave: Rc<dyn Fn()> = {
            let hover = self.clone();
            Rc::new(move || close_after_leave(&hover.active, &hover.timer))
        };
        track_trigger(&widget, enter, leave);
        let hover = self.clone();
        widget.connect_unmap(move |_| hover.close());
    }

    pub fn close(&self) { dismiss_slot(&self.active, &self.timer); }

    #[cfg(test)]
    pub(crate) fn card(&self) -> Option<gtk::Widget> { self.active.borrow().clone() }

    fn open(&self, widget: &gtk::Widget) {
        if let Some(panel) = show_card(&self.context, widget, &self.resolve, &self.active) {
            attach_card_motion(&panel, &self.active, &self.timer);
        }
    }
}

/// Clear the timer slot before calling its one-shot callback. A fired GLib
/// source must not subsequently be removed with its stale SourceId.
fn arm_timer(timer: &TimerSlot, delay: std::time::Duration, f: impl FnOnce() + 'static) {
    cancel_timer(timer);
    let slot = timer.clone();
    let src = glib::timeout_add_local_once(delay, move || {
        slot.borrow_mut().take();
        f();
    });
    *timer.borrow_mut() = Some(src);
}

fn cancel_timer(timer: &TimerSlot) {
    if let Some(src) = timer.borrow_mut().take() { src.remove(); }
}

fn show_card(context: &ContextProvider, widget: &gtk::Widget, resolve: &PersonResolver, active: &CardSlot) -> Option<gtk::Widget> {
    if !crate::window_input::accepts_input(widget) || !widget.is_mapped() { return None; }
    let ctx = context()?;
    let (address, account_id) = resolve()?;
    show_overlay_card(&ctx, widget, &address, account_id.as_ref(), None, active)
}

fn show_overlay_card(ctx: &ProfileCardContext, anchor: &gtk::Widget, address: &EmailAddress,
    account_id: Option<&AccountId>, point: Option<(f64, f64)>, active: &CardSlot) -> Option<gtk::Widget> {
    if !crate::window_input::accepts_input(anchor) || !anchor.is_mapped() { return None; }
    let host = find_host(anchor)?;
    close_current_card();
    let previous = active.borrow_mut().take();
    if let Some(previous) = previous { close_panel(&previous); }
    let content = build_card(ctx, address, account_id);
    let panel: gtk::Widget = gtk::ScrolledWindow::builder()
        .child(&content)
        .propagate_natural_height(true)
        .propagate_natural_width(true)
        .max_content_height(560)
        .max_content_width(520)
        .hscrollbar_policy(gtk::PolicyType::Automatic)
        .halign(gtk::Align::Start)
        .valign(gtk::Align::Start)
        .css_classes(["profile-card-panel"])
        .build().upcast();
    {
        let active = active.clone();
        panel.connect_unmap(move |panel| {
            let mut slot = active.borrow_mut();
            if slot.as_ref() == Some(panel) { *slot = None; }
        });
    }
    CARD_PLACEMENT.with(|slot| *slot.borrow_mut() = Some(CardPlacement {
        panel: panel.downgrade(), anchor: anchor.downgrade(), point,
    }));
    *active.borrow_mut() = Some(panel.clone());
    host.add_overlay(&panel);
    host.set_measure_overlay(&panel, false);
    host.set_clip_overlay(&panel, true);
    panel.set_visible(true);
    host.queue_allocate();
    Some(panel)
}

/// Builds the card's contents for one person.
fn build_card(ctx: &ProfileCardContext, address: &EmailAddress, account_id: Option<&AccountId>) -> gtk::Widget {
    let contact = crate::contacts_view::find_contact_by_address(&ctx.state, &address.address, account_id).map(|(_, entry)| Rc::unwrap_or_clone(entry.record).card);

    let root = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(8)
        .width_request(320)
        .margin_top(10)
        .margin_bottom(10)
        .margin_start(10)
        .margin_end(10)
        .build();
    root.add_css_class("profile-card");

    root.append(&build_header(address, contact.as_ref()));
    root.append(&build_actions(ctx, address, contact.is_some(), account_id.cloned()));
    root.append(&gtk::Separator::new(gtk::Orientation::Horizontal));

    // --- Recent mail (loaded asynchronously from the cache). ---
    root.append(&section_heading("Recent mail"));
    let recent_box = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(2).build();
    root.append(&recent_box);
    spawn_recent_mail(ctx, address, account_id, recent_box.clone());

    // --- Upcoming shared events (already in memory, so synchronous). ---
    let events = {
        let now = chrono::Local::now().naive_local();
        let horizon = Duration::days(EVENT_HORIZON_DAYS);
        shared_upcoming_events(&(ctx.actions.events_for_person)(&address.address), &address.address, now, horizon, UPCOMING_EVENTS_LIMIT)
    };
    root.append(&gtk::Separator::new(gtk::Orientation::Horizontal));
    root.append(&section_heading("Upcoming events"));
    if events.is_empty() {
        root.append(&empty_label("No upcoming shared events"));
    } else {
        for occ in &events {
            root.append(&event_row(ctx, occ));
        }
    }

    root.upcast()
}

/// The card's header: avatar/photo, display name, title · organization and
/// the address itself.
fn build_header(address: &EmailAddress, contact: Option<&VCard>) -> gtk::Widget {
    let row = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(10).build();

    let (avatar, initials_label, picture) = avatar_widget(48);
    initials_label.set_label(&crate::message_header::initials(address.name.as_deref(), &address.address));
    initials_label.add_css_class(crate::message_header::avatar_color_class(&address.address));
    if let Some(texture) = contact.and_then(|card| card.photo.as_ref()).and_then(crate::contacts_view::contact_photo_texture) {
        picture.set_paintable(Some(&texture));
    }
    row.append(&avatar);
    // The avatar (initials/photo) identifies the person: blurred by privacy mode.
    crate::privacy::mark(&avatar);

    let text = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(1)
        .hexpand(true)
        .valign(gtk::Align::Center)
        .build();
    let name = contact.map(crate::contacts_view::vcard_display_name).unwrap_or_else(|| address.display_label().to_string());
    let name_label = gtk::Label::builder().label(&name).xalign(0.0).wrap(true).css_classes(["heading"]).build();
    text.append(&name_label);

    let secondary = contact.and_then(|card| {
        let org = card
            .organization
            .as_ref()
            .map(|parts| parts.iter().map(|p| p.trim()).filter(|p| !p.is_empty()).collect::<Vec<_>>().join(" / "))
            .filter(|s| !s.is_empty());
        let title = card.title.as_deref().map(str::trim).filter(|s| !s.is_empty());
        match (title, org) {
            (Some(t), Some(o)) => Some(format!("{t} · {o}")),
            (Some(t), None) => Some(t.to_string()),
            (None, Some(o)) => Some(o),
            (None, None) => None,
        }
    });
    if let Some(secondary) = secondary {
        text.append(&gtk::Label::builder().label(&secondary).xalign(0.0).wrap(true).css_classes(["caption", "dim-label"]).build());
    }
    if let Some(phones) = contact.map(|card| {
        card.telephones
            .iter()
            .map(|phone| phone.number.trim())
            .filter(|number| !number.is_empty())
            .collect::<Vec<_>>()
            .join(" · ")
    }) {
        if !phones.is_empty() {
            text.append(&gtk::Label::builder().label(&phones).xalign(0.0).wrap(true).css_classes(["caption", "dim-label"]).build());
        }
    }
    text.append(&gtk::Label::builder().label(&address.address).xalign(0.0).wrap(true).css_classes(["caption"]).build());
    // Name, title/organization, phones and address all live in this column.
    crate::privacy::mark(&text);
    row.append(&text);

    row.upcast()
}

/// The action row: Send email · Schedule meeting · Add/Edit contact · People.
fn build_actions(ctx: &ProfileCardContext, address: &EmailAddress, has_contact: bool, account_id: Option<AccountId>) -> gtk::Widget {
    let row = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(4).build();

    let send = action_button("mail-send-symbolic", "Send email");
    {
        let actions = ctx.actions.clone();
        let address = address.clone();
        let account_id = account_id.clone();
        send.connect_clicked(move |_| { close_current_card(); (actions.send_email)(&address, account_id.clone()); });
    }
    row.append(&send);

    let schedule = action_button("x-office-calendar-symbolic", "Schedule");
    {
        let actions = ctx.actions.clone();
        let address = address.clone();
        schedule.connect_clicked(move |_| { close_current_card(); (actions.schedule_meeting)(&address); });
    }
    row.append(&schedule);

    if has_contact {
        let edit = action_button("document-edit-symbolic", "Edit contact");
        {
            let actions = ctx.actions.clone();
            let address = address.clone();
            edit.connect_clicked(move |_| { close_current_card(); (actions.edit_contact)(&address); });
        }
        row.append(&edit);
    } else {
        let add = action_button("contact-new-symbolic", "Add to contacts");
        {
            let actions = ctx.actions.clone();
            let address = address.clone();
            add.connect_clicked(move |_| { close_current_card(); (actions.add_contact)(&address); });
        }
        row.append(&add);
    }

    row.upcast()
}

/// Loads the person's most recent cached messages off the GTK thread and
/// fills `container` (or a dim "No recent messages" note) when they arrive.
fn spawn_recent_mail(ctx: &ProfileCardContext, address: &EmailAddress, account_id: Option<&AccountId>, container: gtk::Box) {
    let query = lookout_mail::SearchQuery {
        from: vec![address.address.clone()],
        ..Default::default()
    };
    let caches: Vec<std::sync::Arc<lookout_mail::Cache>> = {
        let state = ctx.state.borrow();
        match account_id {
            Some(id) => state.accounts.get(id).and_then(|handle| handle.address_cache.clone()).into_iter().collect(),
            None => state.accounts.values().filter_map(|handle| handle.address_cache.clone()).collect(),
        }
    };
    if caches.is_empty() {
        container.append(&empty_label("No recent messages"));
        return;
    }

    let receivers: Vec<async_channel::Receiver<Vec<EmailSummary>>> = caches
        .into_iter()
        .map(|cache| {
            let query = query.clone();
            crate::window::spawn_cache_read(&ctx.worker, cache, move |cache| cache.search_query(&query, None, RECENT_MAIL_LIMIT).unwrap_or_default())
        })
        .collect();

    let actions = ctx.actions.clone();
    glib::spawn_future_local(async move {
        let mut messages: Vec<EmailSummary> = Vec::new();
        for receiver in receivers {
            if let Ok(found) = receiver.recv().await {
                messages.extend(found);
            }
        }
        messages.sort_by_key(|message| std::cmp::Reverse(message.date));
        messages.truncate(RECENT_MAIL_LIMIT);
        if messages.is_empty() {
            container.append(&empty_label("No recent messages"));
            return;
        }
        for message in &messages {
            container.append(&message_row(&actions, message));
        }
    });
}

/// One recent-mail row: the subject, with the date on the right.
fn message_row(actions: &ProfileCardActions, message: &EmailSummary) -> gtk::Widget {
    let row = gtk::Box::builder().orientation(gtk::Orientation::Horizontal).spacing(8).build();
    let subject = gtk::Label::builder()
        .label(message.subject.as_deref().unwrap_or("(no subject)"))
        .xalign(0.0)
        .hexpand(true)
        .ellipsize(gtk::pango::EllipsizeMode::End)
        .build();
    let date = gtk::Label::builder()
        .label(message.date.with_timezone(&chrono::Local).format("%d/%m/%Y").to_string())
        .css_classes(["caption", "dim-label"])
        .valign(gtk::Align::Center)
        .build();
    row.append(&subject);
    row.append(&date);

    let button = gtk::Button::builder().child(&row).css_classes(["flat", "profile-card-row"]).build();
    // Subject/date are content: blurred by privacy mode.
    crate::privacy::mark_content(&button);
    let actions = actions.clone();
    let message = message.clone();
    button.connect_clicked(move |_| { close_current_card(); (actions.open_message)(&message); });
    // The card closes before switching to the selected message.
    button.upcast()
}

/// One upcoming-event row: the title, with its date/time underneath.
fn event_row(ctx: &ProfileCardContext, occ: &EventOccurrence) -> gtk::Widget {
    let (start, _end) = crate::calendar_view::local_span(occ);
    let time = if occ.all_day {
        start.format("%a %d %b").to_string()
    } else {
        start.format("%a %d %b %H:%M").to_string()
    };

    let text = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(0).hexpand(true).build();
    text.append(
        &gtk::Label::builder()
            .label(occ.summary.as_deref().unwrap_or("(no subject)"))
            .xalign(0.0)
            .ellipsize(gtk::pango::EllipsizeMode::End)
            .build(),
    );
    text.append(&gtk::Label::builder().label(&time).xalign(0.0).css_classes(["caption", "dim-label"]).build());

    let button = gtk::Button::builder().child(&text).css_classes(["flat", "profile-card-row"]).build();
    // Event title/time are content: blurred by privacy mode.
    crate::privacy::mark_content(&button);
    let actions = ctx.actions.clone();
    let occ = occ.clone();
    button.connect_clicked(move |_| { close_current_card(); (actions.open_event)(&occ); });
    button.upcast()
}

/// A section caption ("Recent mail", "Upcoming events").
fn section_heading(text: &str) -> gtk::Widget {
    gtk::Label::builder()
        .label(text)
        .xalign(0.0)
        .css_classes(["caption", "dim-label"])
        .margin_top(2)
        .build()
        .upcast()
}

/// A dim empty-state note.
fn empty_label(text: &str) -> gtk::Widget {
    let label = gtk::Label::builder()
        .label(text)
        .xalign(0.0)
        .css_classes(["caption", "dim-label"])
        .margin_top(2)
        .margin_bottom(2)
        .build();
    crate::privacy::mark_ui(&label);
    label.upcast()
}

/// A flat icon + label button, matching the reading pane's action cluster.
/// The shared avatar widget: a coloured circle with initials, and an optional
/// photo over it (a photo with no paintable leaves the initials visible).
fn avatar_widget(size: i32) -> (gtk::Overlay, gtk::Label, gtk::Picture) {
    let label = gtk::Label::builder().css_classes(["avatar-circle"]).build();
    let picture = gtk::Picture::builder().content_fit(gtk::ContentFit::Cover).css_classes(["avatar-photo"]).build();
    let overlay = gtk::Overlay::builder()
        .width_request(size)
        .height_request(size)
        .halign(gtk::Align::Start)
        .valign(gtk::Align::Start)
        .child(&label)
        .build();
    overlay.add_overlay(&picture);
    (overlay, label, picture)
}

/// The conversation WebView sends coordinates for the sender reference.
/// Use the same window-local overlay as GTK contact labels, never a
/// detached popover anchored to a separate WebKit native surface.
pub fn show_person_card_at(context: ContextProvider, anchor: &impl IsA<gtk::Widget>, address: &EmailAddress, account_id: Option<AccountId>, x: f64, y: f64) {
    let Some(ctx) = context() else { return };
    let active = Rc::new(RefCell::new(None));
    let _ = show_overlay_card(&ctx, anchor.as_ref(), address, account_id.as_ref(), Some((x, y)), &active);
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use lookout_core::{Attendee, AttendeeRole, CalendarId, EventUid};

    fn occurrence(summary: &str, start: chrono::DateTime<Utc>, organizer: Option<&str>, attendees: &[&str]) -> EventOccurrence {
        EventOccurrence {
            uid: EventUid(format!("{summary}@example.com")),
            calendar_id: CalendarId("cal1".into()),
            summary: Some(summary.to_string()),
            description: None,
            location: None,
            start,
            end: start + Duration::hours(1),
            all_day: false,
            time_zone: None,
            rrule: None,
            recurrence_id: None,
            exdates: Vec::new(),
            master_start: None,
            master_end: None,
            href: None,
            etag: None,
            master_href: None,
            master_etag: None,
            sequence: 0,
            attendees: attendees
                .iter()
                .map(|a| Attendee {
                    address: EmailAddress::new(*a),
                    role: AttendeeRole::Required,
                    status: Default::default(),
                })
                .collect(),
            organizer: organizer.map(EmailAddress::new),
            schedule_agent: None,
            categories: Vec::new(),
            sensitivity: Default::default(),
            show_as: Default::default(),
            status: Default::default(),
            reminder_minutes_before: None,
            conference_url: None,
            attachments: Vec::new(),
        }
    }

    #[test]
    fn shared_upcoming_events_keeps_only_the_persons_future_events() {
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap().naive_utc();
        let past = occurrence("Past", Utc.with_ymd_and_hms(2026, 5, 1, 12, 0, 0).unwrap(), None, &["ada@example.com"]);
        let attended = occurrence("Standup", Utc.with_ymd_and_hms(2026, 6, 2, 9, 0, 0).unwrap(), None, &["ada@example.com"]);
        let organized = occurrence("Review", Utc.with_ymd_and_hms(2026, 6, 3, 9, 0, 0).unwrap(), Some("ada@example.com"), &[]);
        let unrelated = occurrence("Other", Utc.with_ymd_and_hms(2026, 6, 4, 9, 0, 0).unwrap(), None, &["bob@example.com"]);

        let result = shared_upcoming_events(&[past, attended, organized, unrelated], "ada@example.com", now, Duration::days(90), 10);
        let summaries: Vec<&str> = result.iter().filter_map(|occ| occ.summary.as_deref()).collect();
        assert_eq!(summaries, vec!["Standup", "Review"]);
    }

    #[test]
    fn shared_upcoming_events_matches_organizer_case_insensitively() {
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap().naive_utc();
        let occ = occurrence("Review", Utc.with_ymd_and_hms(2026, 6, 3, 9, 0, 0).unwrap(), Some("ADA@example.com"), &[]);
        assert_eq!(shared_upcoming_events(&[occ], "ada@example.com", now, Duration::days(90), 10).len(), 1);
    }

    #[test]
    fn shared_upcoming_events_respects_the_limit() {
        let now = Utc.with_ymd_and_hms(2026, 6, 1, 12, 0, 0).unwrap().naive_utc();
        let occurrences: Vec<EventOccurrence> = (0..5)
            .map(|i| occurrence("E", Utc.with_ymd_and_hms(2026, 6, 2 + i, 9, 0, 0).unwrap(), None, &["ada@example.com"]))
            .collect();
        assert_eq!(shared_upcoming_events(&occurrences, "ada@example.com", now, Duration::days(90), 3).len(), 3);
    }

    #[test]
    fn hover_timer_clears_its_slot_when_it_fires() {
        if !crate::gtk_test::gtk_ready() {
            return;
        }
        let timer: Rc<RefCell<Option<glib::SourceId>>> = Rc::new(RefCell::new(None));
        let fired = Rc::new(std::cell::Cell::new(false));
        let fired_in_timer = fired.clone();
        arm_timer(&timer, std::time::Duration::ZERO, move || fired_in_timer.set(true));
        let context = glib::MainContext::default();
        while !fired.get() {
            context.iteration(true);
        }
        assert!(timer.borrow().is_none());
        // Leaving or clicking after the card opened: removing the fired
        // source's stale id used to panic here.
        cancel_timer(&timer);
    }

    #[test]
    fn cancelled_hover_timer_never_fires() {
        if !crate::gtk_test::gtk_ready() {
            return;
        }
        let timer: Rc<RefCell<Option<glib::SourceId>>> = Rc::new(RefCell::new(None));
        let fired = Rc::new(std::cell::Cell::new(false));
        let fired_in_timer = fired.clone();
        arm_timer(&timer, std::time::Duration::ZERO, move || fired_in_timer.set(true));
        cancel_timer(&timer);
        assert!(timer.borrow().is_none());
        let context = glib::MainContext::default();
        while context.iteration(false) {}
        assert!(!fired.get());
    }
}
