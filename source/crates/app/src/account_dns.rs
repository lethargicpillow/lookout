//! Shared bounded DNS discovery for account setup. Use the operating
//! system resolver (including VPN DNS), not a public DoH service.
use super::domain;
use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Srv {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub host: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Mx {
    pub priority: u16,
    pub host: String,
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn query(name: &str, kind: i32) -> Option<Vec<u8>> {
    use std::ffi::{c_char, c_int, CString};
    #[link(name = "resolv")]
    extern "C" {
        fn res_query(name: *const c_char, class: c_int, kind: c_int, answer: *mut u8, answer_len: c_int) -> c_int;
    }
    let name = CString::new(format!("{}.", name.trim_end_matches('.'))).ok()?;
    let mut packet = vec![0u8; 65535];
    // SAFETY: live NUL-terminated name, writable output buffer of exact size.
    let len = unsafe { res_query(name.as_ptr(), 1, kind, packet.as_mut_ptr(), packet.len() as c_int) };
    if len <= 0 || len as usize > packet.len() { return None; }
    packet.truncate(len as usize);
    Some(packet)
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn query(_name: &str, _kind: i32) -> Option<Vec<u8>> { None }

fn dns_u16(packet: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*packet.get(i)?, *packet.get(i + 1)?]))
}

// DNS compression can reference a previous label. Bound both the number of
// jumps and the expanded name so malformed packets cannot loop or allocate
// without limit. The returned offset is the end of the original wire name.
pub(super) fn dns_name(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut pos = start;
    let mut end = None;
    let mut name = String::new();
    for _ in 0..128 {
        let count = *packet.get(pos)? as usize;
        if count == 0 {
            return Some((name, end.unwrap_or(pos + 1)));
        }
        if count & 0xc0 == 0xc0 {
            let next = ((count & 0x3f) << 8) | *packet.get(pos + 1)? as usize;
            if next >= pos {
                return None;
            }
            end.get_or_insert(pos + 2);
            pos = next;
            continue;
        }
        if count > 63 {
            return None;
        }
        let label = std::str::from_utf8(packet.get(pos + 1..pos + 1 + count)?).ok()?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(label);
        if name.len() > 253 {
            return None;
        }
        pos += count + 1;
    }
    None
}

// Parse only answer RRs. Check the response question, then restrict
// records to the queried owner or its CNAME chain. Ignore additional data.
#[derive(Debug)]
struct Record {
    owner: String,
    kind: u16,
    start: usize,
    end: usize,
}

fn records(packet: &[u8], question: Option<(&str, u16)>) -> Option<Vec<Record>> {
    let flags = dns_u16(packet, 2)?;
    if flags & 0x8000 == 0 || flags & 0x7a0f != 0 { return None; }
    let questions = dns_u16(packet, 4)? as usize;
    let answers = dns_u16(packet, 6)? as usize;
    if questions > 16 || answers > 256 || (question.is_some() && questions != 1) { return None; }
    let mut pos = 12;
    for _ in 0..questions {
        let (name, end) = dns_name(packet, pos)?;
        if let Some((expected, kind)) = question {
            if !name.eq_ignore_ascii_case(expected) || dns_u16(packet, end)? != kind || dns_u16(packet, end + 2)? != 1 { return None; }
        }
        pos = end + 4;
        packet.get(..pos)?;
    }
    let mut result = Vec::new();
    for _ in 0..answers {
        let (owner, end) = dns_name(packet, pos)?;
        let kind = dns_u16(packet, end)?;
        let class = dns_u16(packet, end + 2)?;
        let length = dns_u16(packet, end + 8)? as usize;
        let start = end + 10;
        pos = start + length;
        packet.get(..pos)?;
        if class == 1 {
            result.push(Record { owner: owner.to_ascii_lowercase(), kind, start, end: pos });
        }
    }
    if let Some((name, _)) = question {
        let mut owners = HashSet::from([name.to_ascii_lowercase()]);
        for _ in 0..8 {
            let mut changed = false;
            for r in result.iter().filter(|r| r.kind == 5) {
                if owners.contains(&r.owner) {
                    let (target, end) = dns_name(packet, r.start)?;
                    if end != r.end { return None; }
                    changed |= owners.insert(target.to_ascii_lowercase());
                }
            }
            if !changed { break; }
        }
        result.retain(|r| owners.contains(&r.owner));
    }
    Some(result)
}

pub(super) fn parse_srv(packet: &[u8], question: Option<&str>) -> Option<Vec<Srv>> {
    let mut result = Vec::new();
    for r in records(packet, question.map(|q| (q, 33)))? {
        if r.kind != 33 || r.end - r.start < 7 { continue; }
        let priority = dns_u16(packet, r.start)?;
        let weight = dns_u16(packet, r.start + 2)?;
        let port = dns_u16(packet, r.start + 4)?;
        let (host, end) = dns_name(packet, r.start + 6)?;
        if end != r.end { return None; }
        // "." explicitly means this service is unavailable.
        let Some(host) = domain(&format!("x@{host}")) else { continue };
        if port != 0 { result.push(Srv { priority, weight, port, host }); }
    }
    result.sort_by_key(|r| (r.priority, std::cmp::Reverse(r.weight)));
    let mut seen = HashSet::new();
    result.retain(|r| seen.insert((r.host.clone(), r.port)));
    result.truncate(16);
    Some(result)
}

fn parse_mx(packet: &[u8], question: Option<&str>) -> Option<Vec<Mx>> {
    let mut result = Vec::new();
    for r in records(packet, question.map(|q| (q, 15)))? {
        if r.kind != 15 || r.end - r.start < 3 { continue; }
        let priority = dns_u16(packet, r.start)?;
        let (host, end) = dns_name(packet, r.start + 2)?;
        if end != r.end { return None; }
        // Null MX is not a provider hostname.
        if host.is_empty() { continue; }
        if let Some(host) = domain(&format!("x@{host}")) { result.push(Mx { priority, host }); }
    }
    result.sort_by_key(|r| r.priority);
    let mut seen = HashSet::new();
    result.retain(|r| seen.insert(r.host.clone()));
    result.truncate(8);
    Some(result)
}

pub(super) fn srv(name: &str) -> Vec<Srv> {
    query(name, 33).and_then(|p| parse_srv(&p, Some(name))).unwrap_or_default()
}

pub(super) fn mx(name: &str) -> Vec<Mx> {
    query(name, 15).and_then(|p| parse_mx(&p, Some(name))).unwrap_or_default()
}

// Use only published MX host suffixes as ISPDB lookup keys. Never use the
// inbound SMTP MX server directly as a client submission server. No host
// table or hard-coded provider domains.
pub(super) fn mx_catalog_domains(original: &str, records: &[Mx]) -> Vec<String> {
    let mut seen = HashSet::from([original.to_owned()]);
    let mut result = Vec::new();
    // Prefer the lowest-priority MX set; try the exact name and then
    // successively less specific suffixes. At most 12 HTTPS catalog probes.
    for r in records {
        let mut suffix = r.host.as_str();
        while suffix.contains('.') {
            if seen.insert(suffix.to_owned()) { result.push(suffix.to_owned()); }
            if result.len() >= 12 { return result; }
            let Some((_, rest)) = suffix.split_once('.') else { break };
            suffix = rest;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(kind: u16, rdata: &[u8]) -> Vec<u8> {
        let mut p = vec![0, 1, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0];
        p.push(0); // root owner (synthetic packet)
        p.extend_from_slice(&kind.to_be_bytes());
        p.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
        p.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        p.extend_from_slice(rdata);
        p
    }

    #[test]
    fn account_dns_mx_is_only_a_catalog_hint() {
        let mut data = vec![0, 10];
        data.extend_from_slice(b"\x03mx1\x04mail\x06hoster\x03com\0");
        let p = packet(15, &data);
        let mx = parse_mx(&p, None).unwrap();
        assert_eq!(mx[0], Mx { priority: 10, host: "mx1.mail.hoster.com".into() });
        assert_eq!(mx_catalog_domains("customer.test", &mx), ["mx1.mail.hoster.com", "mail.hoster.com", "hoster.com"]);
        assert!(parse_mx(&p[..p.len()-1], None).is_none());
        assert!(parse_mx(&packet(15, &[0, 0, 0]), None).unwrap().is_empty());
        assert!(parse_mx(&p, Some("customer.test")).is_none());
    }

    #[test]
    fn account_dns_srv_preserves_nonstandard_port_and_rejects_null() {
        let mut data = vec![0, 2, 0, 5, 0x04, 0x56];
        data.extend_from_slice(b"\x04mail\x07example\x04test\0");
        let p = packet(33, &data);
        let srv = parse_srv(&p, None).unwrap();
        assert_eq!(srv[0], Srv { priority: 2, weight: 5, port: 1110, host: "mail.example.test".into() });
        assert!(parse_srv(&packet(33, &[0,0,0,0,0,0,0]), None).unwrap().is_empty());
        assert!(parse_srv(&p[..p.len()-1], None).is_none());
        assert!(dns_name(&[0xc0, 0], 0).is_none());
    }
}
