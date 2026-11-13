//! Opt-in Exchange OAB refresh, scoped to the configured DavMail account.
//! The helper uses the system Python NTLM stack rather than libcurl, whose
//! newer builds can omit NTLM. Only a verified complete book reaches SQLite.
use std::{cell::RefCell, collections::{HashMap, HashSet}, io::Write, path::{Path, PathBuf}, process::{Command, Stdio}, rc::Rc, time::{Duration, Instant}};
use gtk::{glib, prelude::*};
use lookout_core::AccountId;
use crate::{app_config::OtherAccount, other_accounts::SecretServiceKeyring, window::UiState, worker::Worker};

const CHECK: Duration = Duration::from_secs(24 * 60 * 60);
const RETRY: Duration = Duration::from_secs(60 * 60);
const HELPER: &str = include_str!("oab_fetch.py");

pub(crate) fn valid_url(value: &str) -> bool {
    reqwest::Url::parse(value).is_ok_and(|u| u.scheme() == "https"
        && u.host_str().is_some() && u.username().is_empty() && u.password().is_none()
        && u.query().is_none() && u.fragment().is_none()
        && u.path().rsplit('/').next().is_some_and(|s| s.eq_ignore_ascii_case("oab.xml")))
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!("lookout-oab-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new().mode(0o700).create(&path).map_err(|_| "Cannot create private OAB temporary directory")?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

fn download(url: &str, login: &str, password: &str, known: Option<String>, dir: &Path) -> Result<Option<String>, String> {
    if !valid_url(url) { return Err("Invalid OAB URL".into()); }
    let input = serde_json::to_vec(&serde_json::json!({
        "url": url, "login": login, "password": password, "known": known
    })).map_err(|_| "Cannot prepare OAB request")?;
    let mut child = Command::new("/usr/bin/python3").arg("-I").arg("-c").arg(HELPER)
        .current_dir(dir).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().map_err(|_| "Cannot start OAB helper")?;
    let written = child.stdin.take().ok_or("OAB helper has no input")?.write_all(&input);
    if written.is_err() { let _ = child.kill(); let _ = child.wait(); return Err("Cannot pass credentials to OAB helper".into()); }
    let output = child.wait_with_output().map_err(|_| "OAB helper failed")?;
    let response = String::from_utf8_lossy(&output.stdout);
    let response = response.trim();
    if !output.status.success() {
        // Only fixed error codes from the helper, never URLs, secrets or HTTP bodies.
        return Err(match response {
            "dependencies" => "Install python3-requests, python3-requests-ntlm and libmspack",
            "authentication" => "OAB authentication rejected",
            "manifest" => "Invalid or ambiguous OAB manifest",
            "integrity" => "OAB integrity check failed",
            "unpack" => "OAB decompression failed",
            "tls" => "OAB TLS certificate or handshake failed",
            "timeout" => "OAB request timed out",
            "connection" => "OAB connection or DNS resolution failed",
            "http_transport" => "OAB HTTP transport failed",
            "helper" => "OAB helper failed internally",
            "http_404" => "OAB manifest or download not found (HTTP 404)",
            "http_503" => "OAB service unavailable (HTTP 503)",
            "http_500" => "OAB server error (HTTP 500)",
            "http_301" | "http_302" | "http_307" | "http_308" => "OAB server returned a redirect",
            _ => "OAB network/helper failure",
        }.into());
    }
    if response == "unchanged" { return Ok(None); }
    if response.len() != 64 || !response.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Invalid OAB helper response".into());
    }
    Ok(Some(response.to_owned()))
}

async fn sync(account: OtherAccount, url: String) -> Result<(bool, i64), String> {
    let password = SecretServiceKeyring::new().load_password(&AccountId(account.id.clone()), "imap").await
        .map_err(|_| "OAB account password unavailable")?;
    tokio::task::spawn_blocking(move || {
        let scratch = Scratch::new()?;
        let known = crate::oab_cache::fingerprint(&account.id);
        let downloaded = download(&url, &account.imap_username, &password, known, &scratch.0)?;
        let updated = downloaded.is_some();
        if let Some(fingerprint) = downloaded {
            crate::oab_cache::import_for_account(&account.id, &scratch.0.join("full.oab"), Some(&fingerprint))
                .map_err(|_| "OAB decode or database import failed")?;
        }
        let checked_at = chrono::Utc::now().timestamp();
        if crate::oab_cache::record_check(&account.id, checked_at).is_err() {
            tracing::warn!("Could not persist GAL check timestamp");
        }
        Ok((updated, checked_at))
    }).await.map_err(|_| "OAB background task failed")?
}

#[derive(Default)]
struct CheckStatus {
    last_success: Option<i64>,
    error: Option<String>,
}

fn initial_status(id: &str) -> CheckStatus {
    CheckStatus { last_success: crate::oab_cache::last_check(id), error: None }
}

fn last_check_text(timestamp: Option<i64>) -> String {
    match timestamp.and_then(|seconds| chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, 0)) {
        Some(time) => format!("Last checked: {}", time.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M")),
        None => "Not checked yet".into(),
    }
}

/// Manual and scheduled checks share one in-flight guard and retry schedule.
/// GTK only schedules work; network and all snapshot writes run off-thread.
pub(crate) fn start(
    state: Rc<RefCell<UiState>>,
    worker: Rc<Worker>,
    refresh: Rc<dyn Fn(&str)>,
    button: &gtk::Button,
    label: &gtk::Label,
) -> Rc<dyn Fn()> {
    let due = Rc::new(RefCell::new(HashMap::<(String, String), Instant>::new()));
    let running = Rc::new(RefCell::new(HashSet::<String>::new()));
    let statuses = Rc::new(RefCell::new(HashMap::<String, CheckStatus>::new()));

    let repaint: Rc<dyn Fn()> = {
        let state = state.clone();
        let running = running.clone();
        let statuses = statuses.clone();
        let button = button.downgrade();
        let label = label.downgrade();
        Rc::new(move || {
            let (Some(button), Some(label)) = (button.upgrade(), label.upgrade()) else { return };
            let (id, offline, configured) = {
                let st = state.borrow();
                let id = st.contacts_directory_active.then(|| st.contacts_directory_account.clone()).flatten();
                let configured = id.as_ref().is_some_and(|id| {
                    let config = st.app_config.borrow();
                    st.account_enabled(id) && config.oab_urls.get(&id.0).is_some_and(|url| valid_url(url))
                        && config.other_accounts.iter().any(|a| a.id == id.0 && crate::other_accounts::davmail_accounts(a).is_some())
                });
                (id, st.work_offline, configured)
            };
            button.set_visible(configured);
            label.set_visible(configured);
            if !configured { return; }
            let Some(id) = id else { return };
            let busy = running.borrow().contains(&id.0);
            button.set_sensitive(!offline && !busy);
            let mut statuses = statuses.borrow_mut();
            let status = statuses.entry(id.0.clone()).or_insert_with(|| initial_status(&id.0));
            let last = last_check_text(status.last_success);
            let text = if busy { format!("Checking GAL… · {last}") }
                else if offline { format!("Offline · {last}") }
                else if status.error.is_some() { format!("Update failed · {last}") }
                else { last.clone() };
            label.set_label(&text);
            let tooltip = match &status.error {
                Some(error) => format!("{text}\n{error}\nPrevious address book retained."),
                None => text,
            };
            label.set_tooltip_text(Some(&tooltip));
        })
    };

    let schedule: Rc<dyn Fn(Option<String>)> = {
        let state = state.clone();
        let repaint = repaint.clone();
        Rc::new(move |manual| {
            let accounts = {
                let st = state.borrow();
                if st.work_offline { return; }
                let config = st.app_config.borrow();
                config.other_accounts.iter().filter(|a| st.account_enabled(&AccountId(a.id.clone())))
                    .filter(|a| manual.as_ref().is_none_or(|id| id == &a.id))
                    .filter(|a| crate::other_accounts::davmail_accounts(a).is_some())
                    .filter_map(|a| config.oab_urls.get(&a.id).filter(|url| valid_url(url)).map(|url| (a.clone(), url.clone())))
                    .collect::<Vec<_>>()
            };
            for (account, url) in accounts {
                let key = (account.id.clone(), url.clone());
                if running.borrow().contains(&account.id) { continue; }
                if manual.is_none() && due.borrow().get(&key).is_some_and(|t| *t > Instant::now()) { continue; }
                statuses.borrow_mut().entry(account.id.clone()).or_insert_with(|| initial_status(&account.id));
                running.borrow_mut().insert(account.id.clone());
                let id = account.id.clone();
                let (tx, rx) = async_channel::bounded(1);
                worker.spawn(async move { let _ = tx.send(sync(account, url).await).await; });
                let state = state.clone();
                let due = due.clone();
                let running = running.clone();
                let refresh = refresh.clone();
                let statuses = statuses.clone();
                let repaint = repaint.clone();
                glib::spawn_future_local(async move {
                    let result = rx.recv().await.unwrap_or_else(|_| Err("OAB worker stopped".into()));
                    running.borrow_mut().remove(&id);
                    due.borrow_mut().insert(key, Instant::now() + if result.is_ok() { CHECK } else { RETRY });
                    {
                        let mut statuses = statuses.borrow_mut();
                        let status = statuses.entry(id.clone()).or_default();
                        match &result {
                            Ok((_, timestamp)) => { status.last_success = Some(*timestamp); status.error = None; }
                            Err(message) => status.error = Some(message.clone()),
                        }
                    }
                    repaint();
                    match result {
                        Ok((true, _)) => {
                            tracing::info!("Exchange GAL updated");
                            let query = {
                                let mut st = state.borrow_mut();
                                st.contacts_directory_source = None;
                                if st.contacts_directory_active && st.contacts_directory_account.as_ref().is_some_and(|a| a.0 == id) {
                                    Some(st.contacts_directory_query.clone())
                                } else { None }
                            };
                            if let Some(query) = query { refresh(&query); }
                        }
                        Ok((false, _)) => tracing::debug!("Exchange GAL is current"),
                        Err(message) => tracing::warn!(reason = %message, "Exchange GAL refresh failed; previous snapshot retained"),
                    }
                });
            }
            repaint();
        })
    };

    button.connect_clicked({
        let state = state.clone();
        let schedule = schedule.clone();
        move |_| {
            let id = {
                let st = state.borrow();
                if st.contacts_directory_active { st.contacts_directory_account.clone() } else { None }
            };
            if let Some(id) = id { schedule(Some(id.0)); }
        }
    });
    glib::timeout_add_seconds_local(30, move || {
        schedule(None);
        glib::ControlFlow::Continue
    });
    // Offline/account settings can change while the directory stays open.
    glib::timeout_add_seconds_local(2, {
        let repaint = repaint.clone();
        move || { repaint(); glib::ControlFlow::Continue }
    });
    repaint();
    repaint
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_https_manifest_only() {
        assert!(valid_url("https://exchange.example/OAB/id/oab.xml"));
        for url in ["http://exchange.example/oab.xml", "https://user:pass@exchange.example/oab.xml", "https://exchange.example/oab.xml?x=y", "https://exchange.example/OAB/"] {
            assert!(!valid_url(url));
        }
    }
}
