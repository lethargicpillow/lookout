//! Mail discovery and authenticated Exchange Autodiscover, plus local
//! gateway setup. Credentials are scoped to approved HTTPS hosts. Existing gateway
//! settings are read-only; a conflicting endpoint is never silently reused.
use std::{collections::HashMap, fs, io::Write, net::{SocketAddr, TcpStream}, os::unix::fs::OpenOptionsExt, path::{Path, PathBuf}, process::{Command, Stdio}, time::{Duration, Instant}};
use lookout_mail::Security;
use quick_xml::{events::Event, Reader};

#[path = "exchange_native.rs"]
mod exchange_native;
#[path = "account_dns.rs"]
mod account_dns;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Server {
    pub host: String,
    pub port: u16,
    pub security: Security,
    pub username: String,
}
#[derive(Clone, Debug)]
pub(crate) enum Discovery {
    Mail { imap: Server, smtp: Server, oauth_available: bool, source: &'static str },
    Exchange { ews: Option<String>, oab: Option<String> },
    Microsoft365,
    Google,
    OAuthRequired(String),
    PasswordRequired,
    ApproveHost(String),
}

fn domain(email: &str) -> Option<String> {
    let (local, domain) = email.trim().rsplit_once('@')?;
    if local.is_empty() || local.contains('@') || local.chars().any(|c| c.is_whitespace() || c.is_control()) { return None; }
    let d = domain.to_ascii_lowercase();
    if d.len() > 253 || !d.contains('.') || d.split('.').any(|s| s.is_empty() || s.len() > 63
        || s.starts_with('-') || s.ends_with('-') || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')) { return None; }
    Some(d)
}

fn https_url(value: &str) -> Option<reqwest::Url> {
    let u = reqwest::Url::parse(value.trim()).ok()?;
    (u.scheme() == "https" && u.host_str().is_some() && u.username().is_empty() && u.password().is_none()
        && u.fragment().is_none() && u.query().is_none()).then_some(u)
}

pub(crate) fn valid_ews(value: &str) -> bool {
    https_url(value).is_some_and(|u| u.path().eq_ignore_ascii_case("/ews/exchange.asmx"))
        && value.is_ascii() && !value.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'\\')
}

fn properties(path: &Path) -> Result<HashMap<String, String>, String> {
    let data = fs::read_to_string(path).map_err(|_| "Cannot read existing DavMail configuration")?;
    Ok(data.lines().filter_map(|line| {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with('!') { return None; }
        let (key, value) = line.split_once('=')?;
        Some((key.trim().to_owned(), value.trim().replace("\\:", ":").replace("\\=", "=")))
    }).collect())
}

fn home() -> Result<PathBuf, String> {
    std::env::var_os("HOME").map(PathBuf::from).filter(|p| p.is_absolute()).ok_or_else(|| "Home directory unavailable".into())
}
fn existing_config() -> Result<PathBuf, String> {
    Ok(home()?.join(".config/davmail/davmail.properties"))
}
fn managed_config() -> Result<PathBuf, String> {
    Ok(home()?.join(".config/lookout/davmail.properties"))
}

// Read a bounded XML tree of leaf paths. No DTD, external entities or
// arbitrary redirects. Keeping the parent path distinguishes incoming,
// outgoing and Exchange protocol blocks with identical field names.
fn leaves(xml: &str) -> Option<Vec<(Vec<String>, String)>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut stack = Vec::<String>::new();
    let mut out = Vec::new();
    let mut server_count = 0usize;
    let mut provider_seen = false;
    loop {
        match reader.read_event().ok()? {
            Event::Start(e) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                if name == "emailProvider" && stack == ["clientConfig"] {
                    if provider_seen { return None; }
                    provider_seen = true;
                    if let Some(id) = e.attributes().filter_map(Result::ok).find(|a| a.key.as_ref() == b"id") {
                        let id = id.decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, reader.decoder()).ok()?.into_owned();
                        out.push((vec!["clientConfig".into(), "emailProvider".into(), "@id".into()], id));
                    }
                }
                let server = if (name == "incomingServer" || name == "outgoingServer")
                    && stack == ["clientConfig", "emailProvider"] {
                    server_count += 1;
                    if server_count > 128 { return None; }
                    e.attributes().filter_map(Result::ok).find(|a| a.key.as_ref() == b"type")
                        .map(|a| String::from_utf8_lossy(a.value.as_ref()).into_owned())
                } else { None };
                stack.push(server.map_or(name.clone(), |kind| format!("{name}:{kind}:{server_count}")));
                if stack.len() > 32 { return None; }
            }
            Event::Text(t) => {
                let text = t.decode().ok()?.into_owned();
                let text = quick_xml::escape::unescape(&text).ok()?.into_owned();
                if !text.is_empty() { out.push((stack.clone(), text)); }
                if out.len() > 4096 { return None; }
            }
            Event::End(_) => { stack.pop()?; }
            Event::DocType(_) => return None,
            Event::Eof => break,
            _ => {}
        }
    }
    stack.is_empty().then_some(out)
}

// Discovery and authentication are separate: the ISPDB supplies server
// addresses, ports and available methods. These are stable OAuth provider
// identities, not a host/port table maintained in Lookout.
fn oauth_adapter(issuer: Option<&str>, provider_id: Option<&str>) -> Option<Discovery> {
    match issuer.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("accounts.google.com") | Some("https://accounts.google.com") => return Some(Discovery::Google),
        Some("login.microsoftonline.com") | Some("https://login.microsoftonline.com") |
        Some("login.live.com") | Some("https://login.live.com") => return Some(Discovery::Microsoft365),
        Some(_) => return None,
        None => {}
    }
    // Some ISPDB files predate the oAuth2 metadata. Their stable provider
    // identifier is the fallback identity, independent of email aliases.
    match provider_id.map(str::to_ascii_lowercase).as_deref() {
        Some("googlemail.com") => Some(Discovery::Google),
        Some("hotmail.com") | Some("office365.com") => Some(Discovery::Microsoft365),
        _ => None,
    }
}

#[derive(Debug)]
struct MailEndpoint {
    server: Server,
    password: bool,
    oauth: bool,
}

fn parse_mail_config(xml: &str, email: &str, catalog_domain: Option<&str>) -> Option<Discovery> {
    let entries = leaves(xml)?;
    let value = |path: &[&str]| entries.iter().find(|(p, _)| p.iter().map(String::as_str).eq(path.iter().copied())).map(|(_, v)| v.as_str());
    // A catalog response must describe the queried domain, not an unrelated
    // provider returned by a captive portal, proxy or erroneous redirect.
    let declared: Vec<&str> = entries.iter().filter(|(p, _)| p.iter().map(String::as_str).eq(["clientConfig", "emailProvider", "domain"]))
        .map(|(_, v)| v.as_str()).collect();
    let expected = catalog_domain.map(str::to_owned).or_else(|| domain(email))?;
    if (catalog_domain.is_some() || !declared.is_empty()) && !declared.iter().any(|v| v.eq_ignore_ascii_case(&expected)) {
        return None;
    }
    let provider_id = value(&["clientConfig", "emailProvider", "@id"]);
    let issuer = value(&["clientConfig", "oAuth2", "issuer"]);
    let display = value(&["clientConfig", "emailProvider", "displayName"])
        .or(provider_id).unwrap_or("This mail provider");
    let mut seen = Vec::<String>::new();
    for (path, _) in &entries {
        if path.len() == 4 && path[0] == "clientConfig" && path[1] == "emailProvider"
            && (path[2].starts_with("incomingServer:imap:") || path[2].starts_with("outgoingServer:smtp:"))
            && !seen.contains(&path[2]) {
            seen.push(path[2].clone());
        }
    }
    let mut imap = Vec::new();
    let mut smtp = Vec::new();
    for section in seen {
        // Each block is independent. Never borrow a hostname, port or auth
        // method from a different alternative endpoint.
        let endpoint = (|| -> Option<MailEndpoint> {
            let get = |key: &str| value(&["clientConfig", "emailProvider", &section, key]);
            let host = get("hostname")?.to_owned();
            domain(&format!("x@{host}"))?;
            let port = get("port")?.parse::<u16>().ok().filter(|p| *p != 0)?;
            let security = match get("socketType")? {
                "SSL" => Security::ImplicitTls,
                "STARTTLS" => Security::StartTls,
                _ => return None,
            };
            let username = get("username")?.replace("%EMAILADDRESS%", email)
                .replace("%EMAILLOCALPART%", email.rsplit_once('@')?.0)
                .replace("%EMAILDOMAIN%", &domain(email)?);
            if username.is_empty() || username.contains('%') { return None; }
            let auth = |method: &str| entries.iter().any(|(p, v)| {
                p.iter().map(String::as_str).eq(["clientConfig", "emailProvider", section.as_str(), "authentication"])
                    && v.eq_ignore_ascii_case(method)
            });
            let password = auth("password-cleartext") || auth("password-encrypted");
            let oauth = auth("OAuth2");
            if !password && !oauth { return None; }
            Some(MailEndpoint { server: Server { host, port, security, username }, password, oauth })
        })();
        if let Some(endpoint) = endpoint {
            if section.starts_with("incomingServer:imap:") { imap.push(endpoint); } else { smtp.push(endpoint); }
        }
    }
    if imap.is_empty() || smtp.is_empty() { return None; }
    let oauth_available = imap.iter().any(|e| e.oauth) && smtp.iter().any(|e| e.oauth);
    if oauth_available {
        if let Some(adapter) = oauth_adapter(issuer, provider_id) { return Some(adapter); }
    }
    // An unknown OAuth provider can still use a password/app password if
    // its published endpoints explicitly advertise that alternative.
    if let (Some(imap), Some(smtp)) = (imap.iter().find(|e| e.password), smtp.iter().find(|e| e.password)) {
        return Some(Discovery::Mail { imap: imap.server.clone(), smtp: smtp.server.clone(), oauth_available, source: "Autoconfig" });
    }
    if imap.iter().any(|e| e.oauth) || smtp.iter().any(|e| e.oauth) {
        return Some(Discovery::OAuthRequired(display.to_owned()));
    }
    None
}

fn parse_mail(xml: &str, email: &str) -> Option<Discovery> {
    parse_mail_config(xml, email, None)
}

async fn xml_response(mut response: reqwest::Response) -> Option<String> {
    if !response.status().is_success() || response.content_length().is_some_and(|n| n > 512 * 1024) { return None; }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if bytes.len() + chunk.len() > 512 * 1024 { return None; }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).ok()
}

async fn mail_probe(client: &reqwest::Client, url: String, email: &str) -> Option<Discovery> {
    let mut url = reqwest::Url::parse(&url).ok()?;
    url.query_pairs_mut().append_pair("emailaddress", email);
    let response = client.get(url).send().await.ok()?;
    parse_mail(&xml_response(response).await?, email)
}

// Only the domain (or a DNS-published MX suffix), never credentials or
// the mailbox local part, is sent to the public provider catalog.
async fn catalog_probe(client: &reqwest::Client, key: &str, email: &str) -> Option<Discovery> {
    let response = client.get(format!("https://autoconfig.thunderbird.net/v1.1/{key}")).send().await.ok()?;
    parse_mail_config(&xml_response(response).await?, email, Some(key))
}

fn with_source(mut result: Discovery, source: &'static str) -> Discovery {
    if let Discovery::Mail { source: current, .. } = &mut result { *current = source; }
    result
}

async fn dns_srv(name: String) -> Vec<account_dns::Srv> {
    // libc's DNS resolver is blocking. Keep it off GTK and Tokio's async
    // workers, and bound how long the wizard waits even with dead VPN DNS.
    let task = tokio::task::spawn_blocking(move || account_dns::srv(&name));
    tokio::time::timeout(Duration::from_secs(8), task).await.ok().and_then(Result::ok).unwrap_or_default()
}

async fn dns_mx(name: String) -> Vec<account_dns::Mx> {
    let task = tokio::task::spawn_blocking(move || account_dns::mx(&name));
    tokio::time::timeout(Duration::from_secs(8), task).await.ok().and_then(Result::ok).unwrap_or_default()
}

fn srv_endpoint(email: &str, implicit: &[account_dns::Srv], starttls: &[account_dns::Srv]) -> Option<Server> {
    // Prefer implicit TLS (RFC 8314). Only accept a published host and
    // nonzero port; STARTTLS is mandatory on the other service records.
    let (record, security) = implicit.first().map(|r| (r, Security::ImplicitTls))
        .or_else(|| starttls.first().map(|r| (r, Security::StartTls)))?;
    Some(Server { host: record.host.clone(), port: record.port, security, username: email.to_owned() })
}

async fn srv_discovery(d: &str, email: &str) -> Option<Discovery> {
    let (imaps, imap, submissions, submission) = tokio::join!(
        dns_srv(format!("_imaps._tcp.{d}")),
        dns_srv(format!("_imap._tcp.{d}")),
        dns_srv(format!("_submissions._tcp.{d}")),
        dns_srv(format!("_submission._tcp.{d}")),
    );
    Some(Discovery::Mail {
        imap: srv_endpoint(email, &imaps, &imap)?,
        smtp: srv_endpoint(email, &submissions, &submission)?,
        oauth_available: false,
        source: "DNS SRV",
    })
}

async fn mx_discovery(client: &reqwest::Client, d: &str, email: &str) -> Option<Discovery> {
    let records = dns_mx(d.to_owned()).await;
    let keys = account_dns::mx_catalog_domains(d, &records);
    // Requests run concurrently but selection remains in the DNS/catalog
    // priority order. MX is only a hint and cannot prove the mailbox lives
    // at the returned provider (e.g. an external spam gateway).
    let results = futures_util::future::join_all(keys.iter().map(|key| catalog_probe(client, key, email))).await;
    results.into_iter().flatten().next().map(|r| with_source(r, "DNS MX / ISPDB"))
}

pub(crate) async fn discover(email: &str, password: &str, approved: Vec<String>) -> Result<Discovery, String> {
    let d = domain(email).ok_or("Enter a valid email address")?;
    let client = reqwest::Client::builder().timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none()).build().map_err(|_| "Cannot initialize account discovery")?;
    let (a,b) = tokio::join!(
        mail_probe(&client, format!("https://autoconfig.{d}/mail/config-v1.1.xml"), email),
        mail_probe(&client, format!("https://{d}/.well-known/autoconfig/mail/config-v1.1.xml"), email),
    );
    if let Some(result) = a.or(b) { return Ok(result); }
    // Direct catalog entries are a stronger signal than MX inference.
    if let Some(result) = catalog_probe(&client, &d, email).await {
        return Ok(with_source(result, "ISPDB"));
    }
    let (srv, mx) = tokio::join!(srv_discovery(&d, email), mx_discovery(&client, &d, email));
    if let Some(result) = srv { return Ok(result); }
    // Before accepting an MX-derived provider, try the actual domain's
    // Exchange service. A successful on-premise Autodiscover (including a
    // password/host approval prompt) wins over a third-party MX gateway.
    let address = email.to_owned();
    let password = password.to_owned();
    let result = tokio::task::spawn_blocking(move || exchange_native::discover(&address, &password, &approved))
        .await.map_err(|_| "Autodiscover worker stopped")?;
    match result {
        Ok(result) => Ok(result),
        Err(exchange_native::Error::NotFound) => mx.ok_or_else(|| "No mail configuration found. Check the address or network, or open Advanced server settings.".into()),
        Err(error) => Err(error.message().into()),
    }
}

const PORTS: [u16; 4] = [1143, 1025, 1080, 1389];
fn listening(port: u16) -> bool {
    TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(300)).is_ok()
}
fn service_command(args: &[&str]) -> Result<(), String> {
    let mut child = Command::new("systemctl").arg("--user").args(args)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()
        .map_err(|_| "Cannot start systemctl --user")?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => return Err(format!("DavMail service command failed: {}", args.join(" "))),
            Ok(None) if start.elapsed() < Duration::from_secs(20) => std::thread::sleep(Duration::from_millis(100)),
            _ => { let _ = child.kill(); let _ = child.wait(); return Err("DavMail service command timed out".into()); }
        }
    }
}
fn create_private(path: &Path, data: &str) -> Result<(), String> {
    fs::create_dir_all(path.parent().ok_or("Invalid configuration path")?).map_err(|_| "Cannot create configuration directory")?;
    let mut file = fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(path)
        .map_err(|_| "Cannot create configuration file without overwriting an existing file")?;
    file.write_all(data.as_bytes()).map_err(|_| "Cannot write configuration file".to_owned())
}

fn compatible(p: &HashMap<String, String>, ews: &str) -> bool {
    let eq = |key: &str, value: &str| p.get(key).is_some_and(|v| v.eq_ignore_ascii_case(value));
    eq("davmail.url", ews) && (eq("davmail.mode", "ExchangeEWS") || eq("davmail.mode", "EWS"))
        && eq("davmail.allowRemote", "false") && eq("davmail.bindAddress", "127.0.0.1")
        && eq("davmail.imapPort", "1143") && eq("davmail.smtpPort", "1025")
        && eq("davmail.caldavPort", "1080") && eq("davmail.ldapPort", "1389")
}

// Called only after successful discovery and explicit account setup.
// Do not install packages, overwrite a service, or redirect an existing
// gateway to another organization. Passwords are never in these files.
pub(crate) fn prepare_gateway(ews: &str) -> Result<(), String> {
    if !valid_ews(ews) { return Err("Autodiscover returned an invalid EWS endpoint".into()); }
    let home = home()?;
    let existing = existing_config()?;
    let managed = managed_config()?;
    let unit = home.join(".config/systemd/user/lookout-davmail.service");
    let (config, service) = if existing.exists() {
        if !compatible(&properties(&existing)?, ews) { return Err("Existing DavMail configuration uses a different endpoint or ports. It was not changed.".into()); }
        (existing, "davmail.service")
    } else if managed.exists() {
        if !compatible(&properties(&managed)?, ews) { return Err("Lookout's DavMail gateway is configured for a different endpoint. It was not changed.".into()); }
        (managed, "lookout-davmail.service")
    } else {
        if PORTS.iter().copied().any(listening) { return Err("A local gateway or another service already occupies a required port. No configuration was changed.".into()); }
        if !Path::new("/usr/bin/davmail").is_file() { return Err("Install DavMail first (sudo apt install davmail), then retry.".into()); }
        if unit.exists() { return Err("A Lookout DavMail service already exists. Inspect it before configuring a new gateway.".into()); }
        let config = format!("davmail.server=true\ndavmail.mode=ExchangeEWS\ndavmail.url={ews}\ndavmail.allowRemote=false\ndavmail.bindAddress=127.0.0.1\ndavmail.imapPort=1143\ndavmail.smtpPort=1025\ndavmail.caldavPort=1080\ndavmail.ldapPort=1389\ndavmail.popPort=\ndavmail.enableProxy=false\ndavmail.useSystemProxies=false\ndavmail.disableUpdateCheck=true\n");
        create_private(&managed, &config)?;
        create_private(&unit, "[Unit]\nDescription=Lookout local Exchange gateway\nAfter=network-online.target\n[Service]\nType=simple\nExecStart=/usr/bin/davmail -server %h/.config/lookout/davmail.properties\nRestart=on-failure\nRestartSec=5\n[Install]\nWantedBy=default.target\n")?;
        service_command(&["daemon-reload"])?;
        (managed, "lookout-davmail.service")
    };
    // Reuse a compatible existing service without restarting it.
    let _ = config;
    if PORTS.iter().copied().all(listening) {
        service_command(&["is-active", "--quiet", service])?;
        return Ok(());
    }
    if !PORTS.iter().copied().all(listening) {
        if PORTS.iter().copied().any(listening) { return Err("Only some gateway ports are available. Check the existing DavMail service; no restart was attempted.".into()); }
        service_command(&["enable", "--now", service])?;
    }
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(15) {
        if PORTS.iter().copied().all(listening) {
            service_command(&["is-active", "--quiet", service])?;
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err("DavMail did not open all four local ports. Check the user service journal.".into())
}

/// Verify before saving any secrets or account settings.
pub(crate) async fn verify_credentials(account: &crate::app_config::OtherAccount, imap_password: String, smtp_password: String) -> Result<(), String> {
    use lookout_mail::{AccountConfig, EndpointConfig, Credential};
    let config = AccountConfig {
        account_id: lookout_core::AccountId(account.id.clone()),
        display_name: account.display_name.clone(), email: account.email.clone(),
        mention_addresses: vec![account.email.clone()], mention_names: vec![],
        local_focus_enabled: false, local_focus_contacts: vec![],
        imap: EndpointConfig { host: account.imap_host.clone(), port: account.imap_port,
            security: account.resolved_imap_security(), username: account.imap_username.clone() },
        smtp: EndpointConfig { host: account.smtp_host.clone(), port: account.smtp_port,
            security: account.resolved_smtp_security(), username: account.smtp_username.clone() },
    };
    let timeout = Duration::from_secs(30);
    tokio::time::timeout(timeout, lookout_mail::session::verify_account_login(&config, Credential::Password(imap_password)))
        .await.map_err(|_| "IMAP login timed out. Check the server and network.")?
        .map_err(|_| "IMAP login failed. Check the server, TLS settings, username and password.")?;
    tokio::time::timeout(timeout, lookout_mail::send::verify_smtp_login(&config.smtp, smtp_password))
        .await.map_err(|_| "SMTP login timed out. Check the server and network.")?
        .map_err(|_| "SMTP login failed. Check the server, TLS settings, username and password.")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_setup_catalog_routes_oauth_by_provider_not_email_host() {
        let xml = r#"<clientConfig><emailProvider id="googlemail.com"><domain>custom.example</domain>
        <incomingServer type="imap"><hostname>imap.gmail.com</hostname><port>993</port><socketType>SSL</socketType><username>%EMAILADDRESS%</username><authentication>OAuth2</authentication><authentication>password-cleartext</authentication></incomingServer>
        <outgoingServer type="smtp"><hostname>smtp.gmail.com</hostname><port>465</port><socketType>SSL</socketType><username>%EMAILADDRESS%</username><authentication>OAuth2</authentication><authentication>password-cleartext</authentication></outgoingServer>
        </emailProvider><oAuth2><issuer>accounts.google.com</issuer></oAuth2></clientConfig>"#;
        assert!(matches!(parse_mail_config(xml, "alice@custom.example", Some("custom.example")), Some(Discovery::Google)));
        assert!(parse_mail_config(xml, "alice@other.example", Some("other.example")).is_none());
        let other = xml.replace("accounts.google.com", "login.provider.example").replace("googlemail.com", "provider.example");
        assert!(matches!(parse_mail_config(&other, "alice@custom.example", Some("custom.example")), Some(Discovery::Mail { oauth_available: true, .. })));
    }

    #[test]
    fn account_setup_does_not_mix_endpoint_alternatives() {
        let xml = r#"<clientConfig><emailProvider id="example.test"><domain>example.test</domain>
        <incomingServer type="imap"><hostname>oauth.example.test</hostname><port>993</port><socketType>SSL</socketType><username>%EMAILADDRESS%</username><authentication>OAuth2</authentication></incomingServer>
        <incomingServer type="imap"><hostname>password.example.test</hostname><port>143</port><socketType>STARTTLS</socketType><username>%EMAILLOCALPART%</username><authentication>password-cleartext</authentication></incomingServer>
        <outgoingServer type="smtp"><hostname>smtp.example.test</hostname><port>465</port><socketType>SSL</socketType><username>%EMAILADDRESS%</username><authentication>password-cleartext</authentication></outgoingServer>
        </emailProvider></clientConfig>"#;
        let Some(Discovery::Mail { imap, smtp, .. }) = parse_mail_config(xml, "alice@example.test", Some("example.test")) else { panic!("no password endpoints") };
        assert_eq!(imap.host, "password.example.test");
        assert_eq!(imap.port, 143);
        assert_eq!(imap.username, "alice");
        assert_eq!(imap.security, Security::StartTls);
        assert_eq!(smtp.port, 465);
    }

    #[test]
    fn account_setup_srv_uses_tls_and_published_ports() {
        let implicit = [account_dns::Srv { priority: 0, weight: 1, port: 1993, host: "secure.example.test".into() }];
        let starttls = [account_dns::Srv { priority: 0, weight: 1, port: 1587, host: "submit.example.test".into() }];
        let selected = srv_endpoint("alice@example.test", &implicit, &starttls).unwrap();
        assert_eq!(selected.security, Security::ImplicitTls);
        assert_eq!(selected.port, 1993);
        assert_eq!(selected.username, "alice@example.test");
        let selected = srv_endpoint("alice@example.test", &[], &starttls).unwrap();
        assert_eq!(selected.security, Security::StartTls);
        assert_eq!(selected.port, 1587);
        assert!(srv_endpoint("alice@example.test", &[], &[]).is_none());
    }

    #[test]
    fn account_setup_validates_addresses_and_ews() {
        assert_eq!(domain("alice@Example.test").as_deref(), Some("example.test"));
        assert!(domain("alice@bad/path").is_none());
        assert!(domain("a@foo..test").is_none());
        assert!(valid_ews("https://mail.example.test/EWS/Exchange.asmx"));
        assert!(!valid_ews("http://mail.example.test/EWS/Exchange.asmx"));
        assert!(!valid_ews("https://user:secret@mail.example.test/EWS/Exchange.asmx"));
    }
    #[test]
    fn account_setup_parses_secure_autoconfig() {
        let xml = r#"<clientConfig><emailProvider><incomingServer type="imap"><hostname>imap.example.test</hostname><port>993</port><socketType>SSL</socketType><username>%EMAILADDRESS%</username><authentication>password-cleartext</authentication></incomingServer><outgoingServer type="smtp"><hostname>smtp.example.test</hostname><port>587</port><socketType>STARTTLS</socketType><username>%EMAILLOCALPART%</username><authentication>password-cleartext</authentication></outgoingServer></emailProvider></clientConfig>"#;
        let Some(Discovery::Mail { imap, smtp, .. }) = parse_mail(xml, "alice@example.test") else { panic!("no configuration") };
        assert_eq!(imap.username, "alice@example.test");
        assert_eq!(smtp.username, "alice");
        assert_eq!(smtp.port, 587);
        assert!(matches!(parse_mail(&xml.replace("password-cleartext", "OAuth2"), "alice@example.test"), Some(Discovery::OAuthRequired(_))));
        assert!(parse_mail(&xml.replace("STARTTLS", "plain"), "alice@example.test").is_none());
    }
}
