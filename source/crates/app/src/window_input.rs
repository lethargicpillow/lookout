//! Shared window/input lifecycle. A native popup must never keep a
//! background Lookout window accepting keyboard events after Alt+Tab.
use std::cell::Cell;

use gtk::{gio, glib};
use gtk::prelude::*;

thread_local! {
    static INSTALLED: Cell<bool> = const { Cell::new(false) };
}

pub(crate) fn owner_window(widget: &impl IsA<gtk::Widget>) -> Option<gtk::Window> {
    widget.as_ref().root().and_downcast::<gtk::Window>()
}

pub(crate) fn accepts_input(widget: &impl IsA<gtk::Widget>) -> bool {
    owner_window(widget).is_some_and(|window| window.is_active() && window.is_mapped())
}

pub(crate) fn focus_is_within(widget: &impl IsA<gtk::Widget>) -> bool {
    let widget = widget.as_ref();
    if !accepts_input(widget) { return false; }
    widget.root().and_then(|root| gtk::prelude::RootExt::focus(&root))
        .is_some_and(|focus| focus == *widget || focus.is_ancestor(widget))
}

pub(crate) fn any_active_window() -> bool {
    gtk::Window::list_toplevels().into_iter()
        .filter_map(|widget| widget.downcast::<gtk::Window>().ok())
        .any(|window| window.is_active() && window.is_mapped())
}

/// Snapshot the children before dismissing anything. A popover's closed
/// handler may unparent it or rebuild a menu; never walk a mutating tree.
fn collect_transients(widget: &gtk::Widget, popovers: &mut Vec<gtk::Popover>, panels: &mut Vec<gtk::Widget>) {
    if let Some(popover) = widget.downcast_ref::<gtk::Popover>() {
        if !popovers.iter().any(|p| p == popover) { popovers.push(popover.clone()); }
    }
    if let Some(button) = widget.downcast_ref::<gtk::MenuButton>() {
        if let Some(popover) = button.popover() {
            if !popovers.iter().any(|p| p == &popover) { popovers.push(popover); }
        }
    }
    if widget.has_css_class("compose-completion-panel") {
        panels.push(widget.clone());
    }
    let mut child = widget.first_child();
    while let Some(current) = child {
        child = current.next_sibling();
        collect_transients(&current, popovers, panels);
    }
}

pub(crate) fn dismiss_transients(window: &gtk::Window) {
    let mut popovers = Vec::new();
    let mut panels = Vec::new();
    collect_transients(window.upcast_ref(), &mut popovers, &mut panels);
    for panel in panels { panel.set_visible(false); }
    // Close nested menus first; outside-click callbacks can remove parents.
    for popover in popovers.into_iter().rev() {
        if popover.is_visible() { popover.popdown(); }
    }
}

fn watch_window(window: &gtk::Window) {
    if window.has_css_class("lookout-input-guard") { return; }
    window.add_css_class("lookout-input-guard");
    window.connect_is_active_notify(|window| {
        if window.is_active() { return; }
        // Let the window manager finish a focus transition before closing
        // menus. In particular, do not reparent a widget during FocusOut.
        let weak = window.downgrade();
        glib::idle_add_local_once(move || {
            if let Some(window) = weak.upgrade() {
                if !window.is_active() { dismiss_transients(&window); }
            }
        });
    });
    window.connect_unmap(dismiss_transients);

    // At the root, before GtkListView activation, default buttons, entries
    // or the application's shortcut controller see a key.
    let keys = gtk::EventControllerKey::new();
    keys.set_propagation_phase(gtk::PropagationPhase::Capture);
    let weak = window.downgrade();
    keys.connect_key_pressed(move |_, _, _, _| {
        if weak.upgrade().is_some_and(|window| window.is_active() && window.is_mapped()) {
            glib::Propagation::Proceed
        } else {
            tracing::debug!("blocked keyboard event in inactive Lookout window");
            glib::Propagation::Stop
        }
    });
    window.add_controller(keys);
}

fn watch_windows(model: &gio::ListModel) {
    for index in 0..model.n_items() {
        if let Some(window) = model.item(index).and_downcast::<gtk::Window>() {
            watch_window(&window);
        }
    }
}

/// Watch every GTK toplevel, not just the main ApplicationWindow: popped-out
/// drafts, messages, contacts, calendar editors and dialogs are GtkWindows
/// too, including those not registered with GtkApplication.
pub(crate) fn install() {
    if INSTALLED.with(|installed| installed.replace(true)) { return; }
    let model = gtk::Window::toplevels();
    model.connect_items_changed(|model, _, _, _| watch_windows(model));
    watch_windows(&model);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unrooted_or_hidden_widget_cannot_dispatch_window_input() {
        if !crate::gtk_test::gtk_ready() { return; }
        let button = gtk::Button::new();
        assert!(!accepts_input(&button));
        assert!(!focus_is_within(&button));
        let window = gtk::Window::builder().child(&button).build();
        assert!(!accepts_input(&button));
        assert!(!focus_is_within(&button));
        window.destroy();
    }

    #[test]
    fn dismissal_hides_inline_completion_without_touching_content() {
        if !crate::gtk_test::gtk_ready() { return; }
        let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let field = gtk::Entry::builder().text("unchanged").build();
        let panel = gtk::Box::new(gtk::Orientation::Vertical, 0);
        panel.add_css_class("compose-completion-panel");
        content.append(&field);
        content.append(&panel);
        let window = gtk::Window::builder().child(&content).build();
        assert!(panel.is_visible());
        dismiss_transients(&window);
        assert!(!panel.is_visible());
        assert_eq!(field.text(), "unchanged");
        window.destroy();
    }
}
