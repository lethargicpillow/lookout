//! Local, account-scoped Exchange GAL. The imported OAB never becomes a
//! writable CardDAV contact. SQLite transactions retain the prior snapshot
//! if validation or insertion fails.
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::cell::RefCell;
use std::collections::HashSet;
use rusqlite::{params, Connection, OpenFlags};
use sha2::{Digest, Sha256};
use lookout_core::AccountId;
use lookout_graph::DirectoryPerson;
use crate::window::UiState;
use crate::directory::DirectoryBackend;

fn cache_root() -> PathBuf {
    gtk::glib::user_data_dir().join("lookout").join("gal")
}
fn path_for(account_id: &str) -> PathBuf {
    let digest = Sha256::digest(account_id.as_bytes());
    let name = digest.iter().map(|b| format!("{b:02x}")).collect::<String>();
    cache_root().join(format!("{name}.sqlite"))
}
pub(crate) fn local_paths(state: &Rc<RefCell<UiState>>, account: Option<&AccountId>) -> Vec<PathBuf> {
    let st = state.borrow();
    let config = st.app_config.borrow();
    config.other_accounts.iter()
        .filter(|a| st.account_enabled(&AccountId(a.id.clone())))
        .filter(|a| account.is_none_or(|id| id.0 == a.id))
        .filter_map(|a| crate::other_accounts::davmail_accounts(a).map(|_| path_for(&a.id)))
        .filter(|p| p.is_file()).collect()
}

pub(crate) fn existing_path(account_id: &str) -> Option<PathBuf> {
    let path = path_for(account_id);
    path.is_file().then_some(path)
}

/// Explicit import requires an existing DavMail account, so a corporate
/// cache cannot silently be attributed to another configured mailbox.
pub(crate) fn import_for_email(email: &str, file: &Path) -> Result<(usize, usize), String> {
    let config = crate::app_config::load();
    let matches: Vec<_> = config.other_accounts.iter()
        .filter(|a| a.email.eq_ignore_ascii_case(email) || a.imap_username.eq_ignore_ascii_case(email))
        .filter(|a| crate::other_accounts::davmail_accounts(a).is_some()).collect();
    if matches.len() != 1 { return Err("Expected exactly one configured DavMail account matching that email/login".into()); }
    import_for_account(&matches[0].id, file, None)
}

pub(crate) fn import_for_account(account_id: &str, file: &Path, fingerprint: Option<&str>) -> Result<(usize, usize), String> {
    let bytes = std::fs::read(file).map_err(|e| e.to_string())?;
    let book = crate::oab_decode::decode(&bytes)?;
    tracing::debug!(properties = book.properties.len(), populated_properties = book.present_counts.len(), records = book.declared_records, "Decoded OAB schema");
    let root = cache_root();
    std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    let path = path_for(account_id);
    let count = book.contacts.len();
    let addressable = book.contacts.iter().filter(|c| !c.smtp.trim().is_empty()).count();
    if count == 0 || addressable == 0 { return Err("Refusing to replace GAL with an empty book".into()); }
    write_book_with_fingerprint(&path, &book, fingerprint).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    }
    Ok((count, addressable))
}

pub(crate) fn fingerprint(account_id: &str) -> Option<String> {
    let conn = Connection::open_with_flags(path_for(account_id), OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    conn.query_row("SELECT fingerprint FROM gal_sync LIMIT 1", [], |r| r.get(0)).ok()
}

/// Successful server checks (including unchanged manifests) are recorded
/// separately from the imported data. Older databases need no migration
/// until their first successful check.
pub(crate) fn last_check(account_id: &str) -> Option<i64> {
    let conn = Connection::open_with_flags(path_for(account_id), OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    conn.query_row("SELECT checked_at FROM gal_check LIMIT 1", [], |r| r.get(0)).ok()
}

pub(crate) fn record_check(account_id: &str, checked_at: i64) -> rusqlite::Result<()> {
    write_check(&path_for(account_id), checked_at)
}

fn write_check(path: &Path, checked_at: i64) -> rusqlite::Result<()> {
    let mut conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    let tx = conn.transaction()?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS gal_check (checked_at INTEGER NOT NULL); DELETE FROM gal_check;")?;
    tx.execute("INSERT INTO gal_check VALUES (?1)", [checked_at])?;
    tx.commit()
}

#[cfg(test)]
fn write_book(path: &Path, book: &crate::oab_decode::Book) -> rusqlite::Result<()> {
    write_book_with_fingerprint(path, book, None)
}

fn write_book_with_fingerprint(path: &Path, book: &crate::oab_decode::Book, fingerprint: Option<&str>) -> rusqlite::Result<()> {
    let mut conn = Connection::open(path)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    let tx = conn.transaction()?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS gal_meta (serial INTEGER NOT NULL, declared INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS gal (
          legacy_dn TEXT NOT NULL, smtp TEXT NOT NULL, name TEXT NOT NULL,
          given_name TEXT NOT NULL, surname TEXT NOT NULL, company TEXT NOT NULL,
          department TEXT NOT NULL, title TEXT NOT NULL, office TEXT NOT NULL,
          business_phone TEXT NOT NULL, mobile_phone TEXT NOT NULL,
          object_type INTEGER, display_type INTEGER,
          sort_name TEXT NOT NULL, search_text TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS gal_sort ON gal(sort_name,smtp);
        CREATE TABLE IF NOT EXISTS gal_sync (fingerprint TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS gal_check (checked_at INTEGER NOT NULL);
        DELETE FROM gal; DELETE FROM gal_meta; DELETE FROM gal_sync; DELETE FROM gal_check;")?;
    if let Some(value) = fingerprint {
        tx.execute("INSERT INTO gal_sync VALUES (?1)", [value])?;
    }
    tx.execute("INSERT INTO gal_meta VALUES (?1,?2)", params![book.serial, book.declared_records])?;
    {
        let mut stmt = tx.prepare("INSERT INTO gal VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)")?;
        for c in &book.contacts {
            let sort = c.display_name.to_lowercase();
            let search = [&c.display_name,&c.smtp,&c.given_name,&c.surname,&c.company,&c.department,&c.title,&c.office,&c.business_phone,&c.mobile_phone]
                .map(|v| v.to_lowercase()).join(" ");
            stmt.execute(params![c.legacy_dn,c.smtp,c.display_name,c.given_name,c.surname,c.company,c.department,c.title,c.office,c.business_phone,c.mobile_phone,c.object_type,c.display_type,sort,search])?;
        }
    }
    tx.commit()
}

/// Extended details already stored by the full OAB import. Keep this
/// separate from the lightweight Graph/LDAP recipient suggestion model.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Details {
    pub given_name: String,
    pub surname: String,
    pub department: String,
    pub office: String,
    pub business_phone: String,
    pub mobile_phone: String,
    pub object_type: Option<u32>,
}

pub(crate) fn details(path: &Path, address: &str, name: &str) -> rusqlite::Result<Option<Details>> {
    use rusqlite::OptionalExtension;
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    // The name + SMTP pair is the same as the paged directory entry;
    // gal_sort already indexes sort_name and smtp in existing caches.
    conn.query_row(
        "SELECT given_name,surname,department,office,business_phone,mobile_phone,object_type
         FROM gal WHERE sort_name=?1 AND smtp=?2 ORDER BY rowid LIMIT 1",
        params![name.to_lowercase(), address],
        |row| Ok(Details {
            given_name: row.get(0)?, surname: row.get(1)?,
            department: row.get(2)?, office: row.get(3)?,
            business_phone: row.get(4)?, mobile_phone: row.get(5)?,
            object_type: row.get(6)?,
        }),
    ).optional()
}

pub(crate) struct Page {
    pub people: Vec<DirectoryPerson>,
    pub total: usize,
}
fn optional(s: String) -> Option<String> { (!s.trim().is_empty()).then_some(s) }

fn read_page(path: &Path, query: &str, offset: usize, limit: usize) -> rusqlite::Result<Page> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    let query = query.trim().to_lowercase();
    let total: i64 = conn.query_row("SELECT count(*) FROM gal WHERE trim(smtp) != '' AND instr(search_text,?1)>0", [&query], |r| r.get(0))?;
    let mut stmt = conn.prepare("SELECT name,smtp,title,company,object_type FROM gal WHERE trim(smtp) != '' AND instr(search_text,?1)>0 ORDER BY sort_name,smtp,rowid LIMIT ?2 OFFSET ?3")?;
    let people = stmt.query_map(params![query,limit as i64,offset as i64], |r| {
        let object_type: Option<u32> = r.get(4)?;
        let title: String = r.get(2)?;
        Ok(DirectoryPerson { id: None, name: optional(r.get(0)?), address: r.get(1)?,
            title: if object_type == Some(8) && title.is_empty() { Some("Distribution group".into()) } else { optional(title) },
            company: optional(r.get(3)?) })
    })?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Page { people, total: total as usize })
}

/// One account is the normal fast path. Multiple configured GALs are merged
/// deterministically before slicing; no UI widgets are allocated here.
pub(crate) fn page(paths: &[PathBuf], query: &str, offset: usize, limit: usize) -> Result<Page, String> {
    if paths.len() == 1 { return read_page(&paths[0],query,offset,limit).map_err(|e| e.to_string()); }
    let mut people = Vec::new();
    for p in paths {
        let all = read_page(p,query,0,i64::MAX as usize).map_err(|e| e.to_string())?;
        people.extend(all.people);
    }
    people.sort_by_cached_key(|p| (p.name.as_deref().unwrap_or(&p.address).to_lowercase(),p.address.to_lowercase()));
    let mut seen = HashSet::new();
    people.retain(|p| seen.insert(p.address.to_lowercase()));
    let total = people.len();
    Ok(Page { people: people.into_iter().skip(offset).take(limit).collect(), total })
}

pub(crate) struct Backend {
    pub path: PathBuf,
    pub fallback: Option<crate::ldap_directory::LdapDirectoryBackend>,
}
#[async_trait::async_trait]
impl DirectoryBackend for Backend {
    async fn search(&self, query: &str, limit: usize) -> Vec<DirectoryPerson> {
        let path = self.path.clone();
        let q = query.to_owned();
        match tokio::task::spawn_blocking(move || read_page(&path,&q,0,limit)).await {
            Ok(Ok(page)) if !page.people.is_empty() => return page.people,
            Ok(Err(e)) => tracing::warn!("local GAL read failed: {e}"),
            Err(e) => tracing::warn!("local GAL task failed: {e}"),
            _ => {}
        }
        match &self.fallback { Some(backend) => backend.search(query,limit).await, None => Vec::new() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_import_search_and_paging() {
        let path = std::env::temp_dir().join(format!("lookout-gal-{}.sqlite",uuid::Uuid::new_v4()));
        let mut book = crate::oab_decode::Book { serial: 1, declared_records: 3, properties: vec![], contacts: vec![], present_counts: Default::default() };
        for (name, smtp, kind) in [("Борис","b@example.invalid",6),("Алиса","a@example.invalid",6),("Группа","g@example.invalid",8)] {
            book.contacts.push(crate::oab_decode::Contact { display_name:name.into(),smtp:smtp.into(),object_type:Some(kind),
                department:"Engineering".into(),office:"101".into(),business_phone:"123".into(),mobile_phone:"456".into(),..Default::default() });
        }
        write_book(&path,&book).unwrap();
        let p = read_page(&path,"",0,2).unwrap();
        assert_eq!(p.total,3);
        assert_eq!(p.people[0].name.as_deref(),Some("Алиса"));
        assert_eq!(read_page(&path,"АЛИ",0,100).unwrap().total,1);
        let d = details(&path,"a@example.invalid","Алиса").unwrap().unwrap();
        assert_eq!(d.department,"Engineering");
        assert_eq!(d.office,"101");
        assert_eq!(d.business_phone,"123");
        assert_eq!(d.mobile_phone,"456");
        assert_eq!(d.object_type,Some(6));
        assert!(details(&path,"a@example.invalid","Другой").unwrap().is_none());
        assert_eq!(read_page(&path,"",2,2).unwrap().people[0].title.as_deref(),Some("Distribution group"));
        book.contacts.truncate(1);
        write_book(&path,&book).unwrap();
        assert_eq!(read_page(&path,"",0,10).unwrap().total,1);
        write_check(&path, 123).unwrap();
        write_check(&path, 456).unwrap();
        {
            let conn = Connection::open(&path).unwrap();
            assert_eq!(conn.query_row("SELECT checked_at FROM gal_check", [], |r| r.get::<_, i64>(0)).unwrap(), 456);
            assert_eq!(conn.query_row("SELECT count(*) FROM gal_check", [], |r| r.get::<_, i64>(0)).unwrap(), 1);
        }
        write_book(&path,&book).unwrap();
        {
            let conn = Connection::open(&path).unwrap();
            assert_eq!(conn.query_row("SELECT count(*) FROM gal_check", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
        }
        std::fs::remove_file(path).unwrap();
    }
}
