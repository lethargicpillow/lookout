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
    minus: glib::WeakRef<gtk::Button>,
    plus: glib::WeakRef<gtk::Button>,
    retry: glib::WeakRef<gtk::Button>,
}
impl Preview {
    fn controls(&self) {
        let idle = !self.busy.get();
        let known = self.pages.get() > 0;
        if let Some(label) = self.counter.upgrade() {
            label.set_text(&format!("Page {} / {}   ·   {}%",
                self.page.get(), if known { self.pages.get().to_string() } else { "…".into() }, ZOOM[self.zoom.get()]));
        }
        for (button, enabled) in [
            (&self.previous, self.page.get() > 1),
            (&self.next, known && self.page.get() < self.pages.get()),
            (&self.minus, known && self.zoom.get() > 0),
            (&self.plus, known && self.zoom.get() + 1 < ZOOM.len()),
            (&self.retry, true),
        ] {
            if let Some(button) = button.upgrade() {
                button.set_sensitive(idle && enabled);
            }
        }
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
            self.finish(Err("Could not start PDF preview worker.".into()));
            return;
        }
        let preview = self.clone();
        glib::spawn_future_local(async move {
            let result = rx.recv().await.unwrap_or_else(|_| Err("PDF preview worker stopped.".into()));
            preview.finish(result);
        });
    }

    fn finish(&self, result: Result<Rendered, String>) {
        self.busy.set(false);
        let (Some(picture), Some(status), Some(retry)) =
            (self.picture.upgrade(), self.status.upgrade(), self.retry.upgrade()) else { return; };
        let result = result.and_then(|rendered| {
            self.pages.set(rendered.pages);
            gtk::gdk::Texture::from_bytes(&glib::Bytes::from(rendered.png.as_slice()))
                .map_err(|_| "Could not decode the rendered PDF page.".to_string())
        });
        match result {
            Ok(texture) => {
                picture.set_paintable(Some(&texture));
                picture.set_size_request(texture.width(), texture.height());
                picture.set_visible(true);
                status.set_visible(false);
                retry.set_visible(false);
            }
            Err(message) => {
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
    let bar = gtk::Box::builder().orientation(gtk::Orientation::Horizontal)
        .spacing(8).margin_start(12).margin_end(12).margin_top(8).margin_bottom(8).build();
    let previous = gtk::Button::with_label("Previous");
    let next = gtk::Button::with_label("Next");
    let minus = gtk::Button::with_label("−");
    let plus = gtk::Button::with_label("+");
    minus.set_tooltip_text(Some("Zoom out"));
    plus.set_tooltip_text(Some("Zoom in"));
    let counter = gtk::Label::new(None);
    let retry = gtk::Button::with_label("Retry");
    for button in [&previous, &next] { bar.append(button); }
    bar.append(&counter);
    for button in [&minus, &plus, &retry] { bar.append(button); }
    content.append(&bar);

    let status = gtk::Label::new(None);
    status.set_wrap(true);
    status.set_margin_top(12);
    status.set_margin_start(12);
    status.set_margin_end(12);
    content.append(&status);
    let picture = gtk::Picture::new();
    picture.set_can_shrink(false);
    picture.set_content_fit(gtk::ContentFit::Contain);
    picture.set_halign(gtk::Align::Center);
    picture.set_valign(gtk::Align::Start);
    crate::privacy::mark_blur_all(&picture);
    let scroller = gtk::ScrolledWindow::builder().child(&picture).vexpand(true).hexpand(true).build();
    content.append(&scroller);

    let preview = Rc::new(Preview {
        bytes: Arc::new(bytes.to_vec()), page: Cell::new(1), pages: Cell::new(0),
        zoom: Cell::new(1), busy: Cell::new(false),
        picture: picture.downgrade(), counter: counter.downgrade(), status: status.downgrade(),
        previous: previous.downgrade(), next: next.downgrade(), minus: minus.downgrade(),
        plus: plus.downgrade(), retry: retry.downgrade(),
    });
    for (button, action) in [(&previous, 0), (&next, 1), (&minus, 2), (&plus, 3), (&retry, 4)] {
        let preview = preview.clone();
        button.connect_clicked(move |_| {
            if preview.busy.get() { return; }
            match action {
                0 if preview.page.get() > 1 => preview.page.set(preview.page.get() - 1),
                1 if preview.page.get() < preview.pages.get() => preview.page.set(preview.page.get() + 1),
                2 if preview.zoom.get() > 0 => preview.zoom.set(preview.zoom.get() - 1),
                3 if preview.zoom.get() + 1 < ZOOM.len() => preview.zoom.set(preview.zoom.get() + 1),
                4 => {},
                _ => return,
            }
            preview.begin();
        });
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
