//! Opt-in Exchange OAB refresh, scoped to the configured DavMail account.
//! The helper uses the system Python NTLM stack rather than libcurl, whose
//! newer builds can omit NTLM. Only a verified complete book reaches SQLite.
use std::{cell::RefCell, collections::{HashMap, HashSet}, io::Write, path::{Path, PathBuf}, process::{Command, Stdio}, rc::Rc, time::{Duration, Instant}};
use gtk::glib;
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
            _ => "OAB network/helper failure",
        }.into());
    }
    if response == "unchanged" { return Ok(None); }
    if response.len() != 64 || !response.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Invalid OAB helper response".into());
    }
    Ok(Some(response.to_owned()))
}

async fn sync(account: OtherAccount, url: String) -> Result<bool, String> {
    let password = SecretServiceKeyring::new().load_password(&AccountId(account.id.clone()), "imap").await
        .map_err(|_| "OAB account password unavailable")?;
    tokio::task::spawn_blocking(move || {
        let scratch = Scratch::new()?;
        let known = crate::oab_cache::fingerprint(&account.id);
        let Some(fingerprint) = download(&url, &account.imap_username, &password, known, &scratch.0)? else { return Ok(false); };
        crate::oab_cache::import_for_account(&account.id, &scratch.0.join("full.oab"), Some(&fingerprint))
            .map_err(|_| "OAB decode or database import failed")?;
        Ok(true)
    }).await.map_err(|_| "OAB background task failed")?
}

/// The GTK timer only schedules work. Network, decompression and database
/// writes run off the UI thread. A failure keeps the previous snapshot.
pub(crate) fn start(state: Rc<RefCell<UiState>>, worker: Rc<Worker>, refresh: Rc<dyn Fn(&str)>) {
    let due = Rc::new(RefCell::new(HashMap::<(String, String), Instant>::new()));
    let running = Rc::new(RefCell::new(HashSet::<String>::new()));
    glib::timeout_add_seconds_local(30, move || {
        let accounts = {
            let st = state.borrow();
            if st.work_offline { return glib::ControlFlow::Continue; }
            let config = st.app_config.borrow();
            config.other_accounts.iter().filter(|a| st.account_enabled(&AccountId(a.id.clone())))
                .filter(|a| crate::other_accounts::davmail_accounts(a).is_some())
                .filter_map(|a| config.oab_urls.get(&a.id).filter(|url| valid_url(url)).map(|url| (a.clone(), url.clone())))
                .collect::<Vec<_>>()
        };
        for (account, url) in accounts {
            let key = (account.id.clone(), url.clone());
            if running.borrow().contains(&account.id) || due.borrow().get(&key).is_some_and(|t| *t > Instant::now()) { continue; }
            running.borrow_mut().insert(account.id.clone());
            let id = account.id.clone();
            let (tx, rx) = async_channel::bounded(1);
            worker.spawn(async move { let _ = tx.send(sync(account, url).await).await; });
            let state = state.clone();
            let due = due.clone();
            let running = running.clone();
            let refresh = refresh.clone();
            glib::spawn_future_local(async move {
                let result = rx.recv().await.unwrap_or_else(|_| Err("OAB worker stopped".into()));
                running.borrow_mut().remove(&id);
                due.borrow_mut().insert(key, Instant::now() + if result.is_ok() { CHECK } else { RETRY });
                match result {
                    Ok(true) => {
                        tracing::info!("Exchange GAL updated");
                        let query = {
                            let mut st = state.borrow_mut();
                            st.contacts_directory_source = None;
                            if st.contacts_directory_active && st.contacts_directory_account.as_ref().is_some_and(|a| a.0 == id) {
                                st.contacts_directory_offset = 0;
                                Some(st.contacts_directory_query.clone())
                            } else { None }
                        };
                        if let Some(query) = query { refresh(&query); }
                    }
                    Ok(false) => tracing::debug!("Exchange GAL is current"),
                    Err(message) => tracing::warn!(reason = %message, "Exchange GAL refresh failed; previous snapshot retained"),
                }
            });
        }
        glib::ControlFlow::Continue
    });
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
