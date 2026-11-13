//! Read-only PDF preview using system Poppler utilities. All subprocess and
//! filesystem work runs off the GTK thread; no shell or embedded browser.

use gtk::{glib, prelude::*};
use std::cell::Cell;
use std::fs;
use std::io::Read;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

const ZOOM: [u32; 5] = [75, 100, 125, 150, 200];
const TOOL_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_PNG_BYTES: u64 = 24 * 1024 * 1024;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!("lookout-pdf-{}", uuid::Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_tool(command: &mut Command) -> Result<(), String> {
    let mut child = command.env("LC_ALL", "C").stdin(Stdio::null()).stderr(Stdio::null())
        .spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "PDF preview requires Poppler (install poppler-utils).".to_string()
            } else {
                "Could not start the PDF renderer.".to_string()
            }
        })?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => return Err("Could not read this PDF. It may be encrypted or damaged.".into()),
            Ok(None) if start.elapsed() < TOOL_TIMEOUT => std::thread::sleep(Duration::from_millis(25)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("PDF rendering timed out or failed.".into());
            }
        }
    }
}

fn page_count(info: &str) -> Option<u32> {
    info.lines().find_map(|line| line.strip_prefix("Pages:"))
        .and_then(|value| value.trim().parse::<u32>().ok()).filter(|n| *n > 0)
}

fn render_size(zoom: usize) -> u32 {
    900 * ZOOM[zoom.min(ZOOM.len() - 1)] / 100
}

struct Rendered {
    png: Vec<u8>,
    pages: u32,
}

fn render_page(bytes: &[u8], page: u32, zoom: usize, known_pages: u32) -> Result<Rendered, String> {
    let scratch = Scratch::new().map_err(|_| "Could not create a private PDF preview directory.".to_string())?;
    let input = scratch.0.join("attachment.pdf");
    fs::write(&input, bytes).map_err(|_| "Could not prepare PDF preview.".to_string())?;
    let pages = if known_pages > 0 {
        known_pages
    } else {
        let info_path = scratch.0.join("info.txt");
        let output = fs::File::create(&info_path).map_err(|_| "Could not prepare PDF metadata.".to_string())?;
        run_tool(Command::new("pdfinfo").arg(&input).stdout(Stdio::from(output)))?;
        let mut info = String::new();
        fs::File::open(&info_path)
            .and_then(|f| f.take(256 * 1024).read_to_string(&mut info))
            .map_err(|_| "Could not read PDF metadata.".to_string())?;
        page_count(&info).ok_or_else(|| "Could not determine the PDF page count.".to_string())?
    };
    if page == 0 || page > pages {
        return Err("PDF page is outside the document.".into());
    }
    let page_arg = page.to_string();
    let size_arg = render_size(zoom).to_string();
    let prefix = scratch.0.join("page");
    run_tool(Command::new("pdftoppm")
        .args(["-f", &page_arg, "-l", &page_arg, "-singlefile", "-png", "-scale-to", &size_arg])
        .arg(&input).arg(&prefix).stdout(Stdio::null()))?;
    let image = fs::File::open(scratch.0.join("page.png"))
        .map_err(|_| "PDF renderer did not produce a page.".to_string())?;
    let mut png = Vec::new();
    image.take(MAX_PNG_BYTES + 1).read_to_end(&mut png)
        .map_err(|_| "Could not read the rendered page.".to_string())?;
    if png.is_empty() || png.len() as u64 > MAX_PNG_BYTES {
        return Err("The rendered PDF page is too large or empty.".into());
    }
    Ok(Rendered { png, pages })
}

// Weak widget references avoid cycles with button handlers and let a closed
// preview disappear while a worker finishes its current render.
struct Preview {
    bytes: Arc<Vec<u8>>,
    page: Cell<u32>,
    pages: Cell<u32>,
    zoom: Cell<usize>,
    busy: Cell<bool>,
    picture: glib::WeakRef<gtk::Picture>,
    counter: glib::WeakRef<gtk::Label>,
    status: glib::WeakRef<gtk::Label>,
    previous: glib::WeakRef<gtk::Button>,
    next: glib::WeakRef<gtk::Button>,
    slider: glib::WeakRef<gtk::Scale>,
    zoom_label: glib::WeakRef<gtk::Label>,
    zoom_revision: Cell<u64>,
    rendered_zoom: Cell<Option<usize>>,
    retry: glib::WeakRef<gtk::Button>,
}
impl Preview {
    fn controls(&self) {
        let idle = !self.busy.get();
        let known = self.pages.get() > 0;
        if let Some(label) = self.counter.upgrade() {
            label.set_text(&format!("{} / {}",
                self.page.get(), if known { self.pages.get().to_string() } else { "…".into() }));
        }
        if let Some(label) = self.zoom_label.upgrade() {
            label.set_text(&format!("{}%", ZOOM[self.zoom.get()]));
        }
        if let Some(slider) = self.slider.upgrade() {
            // Do not interrupt a drag when rendering starts. Changes are
            // coalesced and the newest requested zoom wins.
            slider.set_sensitive(known);
        }
        for (button, enabled) in [
            (&self.previous, self.page.get() > 1),
            (&self.next, known && self.page.get() < self.pages.get()),
            (&self.retry, true),
        ] {
            if let Some(button) = button.upgrade() {
                button.set_sensitive(idle && enabled);
            }
        }
    }

    fn request_zoom(self: &Rc<Self>, value: f64) {
        let zoom = value.round().clamp(0.0, (ZOOM.len() - 1) as f64) as usize;
        if self.zoom.replace(zoom) == zoom { return; }
        self.controls();
        let revision = self.zoom_revision.get().wrapping_add(1);
        self.zoom_revision.set(revision);
        let weak = Rc::downgrade(self);
        glib::timeout_add_local_once(Duration::from_millis(180), move || {
            let Some(preview) = weak.upgrade() else { return; };
            if preview.zoom_revision.get() == revision
                && !preview.busy.get()
                && preview.rendered_zoom.get() != Some(preview.zoom.get())
            {
                preview.begin();
            }
        });
    }

    fn begin(self: &Rc<Self>) {
        if self.busy.replace(true) { return; }
        self.controls();
        if let Some(label) = self.status.upgrade() {
            label.set_text("Rendering PDF page…");
            label.set_visible(true);
        }
        if let Some(picture) = self.picture.upgrade() { picture.set_visible(false); }
        if let Some(retry) = self.retry.upgrade() { retry.set_visible(false); }
        let bytes = self.bytes.clone();
        let (page, zoom, pages) = (self.page.get(), self.zoom.get(), self.pages.get());
        let (tx, rx) = async_channel::bounded(1);
        let started = std::thread::Builder::new().name("lookout-pdf-preview".into()).spawn(move || {
            let _ = tx.send_blocking(render_page(&bytes, page, zoom, pages));
        });
        if started.is_err() {
            self.finish(zoom, Err("Could not start PDF preview worker.".into()));
            return;
        }
        let preview = self.clone();
        glib::spawn_future_local(async move {
            let result = rx.recv().await.unwrap_or_else(|_| Err("PDF preview worker stopped.".into()));
            preview.finish(zoom, result);
        });
    }

    fn finish(self: &Rc<Self>, rendered_zoom: usize, result: Result<Rendered, String>) {
        self.busy.set(false);
        if self.picture.upgrade().is_none() { return; }
        // A slider change during a render supersedes that result. Never
        // present a stale zoom or launch concurrent Poppler subprocesses.
        if let Ok(rendered) = &result {
            self.pages.set(rendered.pages);
        }
        if self.zoom.get() != rendered_zoom {
            self.begin();
            return;
        }
        let (Some(picture), Some(status), Some(retry)) =
            (self.picture.upgrade(), self.status.upgrade(), self.retry.upgrade()) else { return; };
        let result = result.and_then(|rendered| {
            self.pages.set(rendered.pages);
            gtk::gdk::Texture::from_bytes(&glib::Bytes::from(rendered.png.as_slice()))
                .map_err(|_| "Could not decode the rendered PDF page.".to_string())
        });
        match result {
            Ok(texture) => {
                self.rendered_zoom.set(Some(rendered_zoom));
                picture.set_paintable(Some(&texture));
                picture.set_size_request(texture.width(), texture.height());
                picture.set_visible(true);
                status.set_visible(false);
                retry.set_visible(false);
            }
            Err(message) => {
                self.rendered_zoom.set(None);
                picture.set_visible(false);
                status.set_text(&message);
                status.set_visible(true);
                retry.set_visible(true);
            }
        }
        self.controls();
    }
}

pub(super) fn show(content: &gtk::Box, bytes: &[u8]) {
    // Only the titlebar is above the document. Navigation and zoom occupy
    // the narrow side rails, not a horizontal toolbar.
    let body = gtk::Box::builder().orientation(gtk::Orientation::Horizontal)
        .vexpand(true).hexpand(true).build();
    let navigation = gtk::Box::builder().orientation(gtk::Orientation::Vertical)
        .spacing(6).margin_start(8).margin_end(8).valign(gtk::Align::Center).build();
    let previous = gtk::Button::from_icon_name("go-up-symbolic");
    previous.set_tooltip_text(Some("Previous page"));
    let next = gtk::Button::from_icon_name("go-down-symbolic");
    next.set_tooltip_text(Some("Next page"));
    let counter = gtk::Label::new(None);
    counter.set_tooltip_text(Some("Current page / Total pages"));
    let retry = gtk::Button::with_label("Retry");
    navigation.append(&previous);
    navigation.append(&counter);
    navigation.append(&next);
    navigation.append(&retry);
    body.append(&navigation);
    body.append(&gtk::Separator::new(gtk::Orientation::Vertical));

    let status = gtk::Label::new(None);
    status.set_wrap(true);
    status.set_justify(gtk::Justification::Center);
    status.set_halign(gtk::Align::Center);
    status.set_valign(gtk::Align::Center);
    status.set_margin_start(12);
    status.set_margin_end(12);
    status.set_can_target(false);
    let picture = gtk::Picture::new();
    picture.set_can_shrink(false);
    picture.set_content_fit(gtk::ContentFit::Contain);
    picture.set_halign(gtk::Align::Center);
    picture.set_valign(gtk::Align::Start);
    crate::privacy::mark_blur_all(&picture);
    let scroller = gtk::ScrolledWindow::builder().child(&picture).vexpand(true).hexpand(true).build();
    let document = gtk::Overlay::new();
    document.set_hexpand(true);
    document.set_vexpand(true);
    document.set_child(Some(&scroller));
    document.add_overlay(&status);
    body.append(&document);
    body.append(&gtk::Separator::new(gtk::Orientation::Vertical));

    let zoom_rail = gtk::Box::builder().orientation(gtk::Orientation::Vertical)
        .spacing(8).margin_start(8).margin_end(8).valign(gtk::Align::Center).build();
    let slider = gtk::Scale::with_range(gtk::Orientation::Vertical, 0.0, (ZOOM.len() - 1) as f64, 1.0);
    slider.set_inverted(true);
    slider.set_draw_value(false);
    slider.set_digits(0);
    slider.set_size_request(-1, 220);
    slider.set_value(1.0);
    slider.set_tooltip_text(Some("PDF zoom"));
    for (index, percent) in ZOOM.iter().enumerate() {
        slider.add_mark(index as f64, gtk::PositionType::Right, Some(&format!("{percent}%")));
    }
    let zoom_label = gtk::Label::new(Some("100%"));
    zoom_rail.append(&slider);
    zoom_rail.append(&zoom_label);
    body.append(&zoom_rail);
    content.append(&body);

    let preview = Rc::new(Preview {
        bytes: Arc::new(bytes.to_vec()), page: Cell::new(1), pages: Cell::new(0),
        zoom: Cell::new(1), busy: Cell::new(false),
        picture: picture.downgrade(), counter: counter.downgrade(), status: status.downgrade(),
        previous: previous.downgrade(), next: next.downgrade(),
        slider: slider.downgrade(), zoom_label: zoom_label.downgrade(),
        zoom_revision: Cell::new(0), rendered_zoom: Cell::new(None), retry: retry.downgrade(),
    });
    for (button, action) in [(&previous, 0), (&next, 1), (&retry, 2)] {
        let preview = preview.clone();
        let scroller = scroller.downgrade();
        button.connect_clicked(move |_| {
            if preview.busy.get() { return; }
            match action {
                0 if preview.page.get() > 1 => preview.page.set(preview.page.get() - 1),
                1 if preview.page.get() < preview.pages.get() => preview.page.set(preview.page.get() + 1),
                2 => {},
                _ => return,
            }
            if action != 2 {
                if let Some(scroller) = scroller.upgrade() {
                    let adjustment = scroller.vadjustment();
                    adjustment.set_value(adjustment.lower());
                }
            }
            preview.begin();
        });
    }
    {
        let preview = preview.clone();
        slider.connect_value_changed(move |slider| preview.request_zoom(slider.value()));
    }
    preview.begin();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdf_metadata_and_zoom_are_bounded() {
        assert_eq!(page_count("Title: Example\nPages:           12\n"), Some(12));
        assert_eq!(page_count("Pages: 0"), None);
        assert_eq!(page_count("Pages: invalid"), None);
        assert_eq!(page_count("Title: no page count"), None);
        assert_eq!(render_size(0), 675);
        assert_eq!(render_size(1), 900);
        assert_eq!(render_size(4), 1800);
        assert_eq!(render_size(usize::MAX), 1800);
    }
}
