/// Copyright (C) <2026>  <Gavin Graham & Contributors>
/// Software released under the GPL3 license
use std::collections::BTreeSet;

use async_imap::types::Fetch;
use chrono::{DateTime, Utc};
use lookout_core::{header_value, importance_from_headers, sensitivity_from_headers, EmailAddress, EmailSummary, MailboxId, SystemFlagBit, ThreadKey, Uid};

/// Decode RFC 2047 words in an IMAP ENVELOPE value using the same MIME
/// parser as message bodies, including legacy Cyrillic and Japanese charsets.
pub fn decode_mime_words(input: &str) -> String {
    if !input.contains("=?") {
        return input.to_owned();
    }
    // Treat the IMAP value as one unstructured header. Never let a newline
    // in that value introduce a second header into the synthetic message.
    let unfolded = input.replace(['\r', '\n'], " ");
    let raw = format!("Subject: {unfolded}\r\n\r\n");
    mail_parser::MessageParser::default()
        .parse(raw.as_bytes())
        .and_then(|message| message.subject().map(str::to_owned))
        .unwrap_or_else(|| input.to_owned())
}

fn cow_to_decoded_string(cow: &[u8]) -> String {
    decode_mime_words(&String::from_utf8_lossy(cow))
}

fn parse_addresses(addrs: &Option<Vec<async_imap::imap_proto::types::Address<'_>>>) -> Vec<EmailAddress> {
    let Some(addrs) = addrs else { return Vec::new() };
    addrs
        .iter()
        .filter_map(|a| {
            let mailbox = a.mailbox.as_ref()?;
            let host = a.host.as_ref()?;
            let address = format!("{}@{}", String::from_utf8_lossy(mailbox), String::from_utf8_lossy(host));
            let name = a.name.as_ref().map(|c| cow_to_decoded_string(c)).filter(|s| !s.is_empty());
            Some(EmailAddress { name, address })
        })
        .collect()
}

/// Builds an [`EmailSummary`] from a `UID FETCH ... (UID FLAGS ENVELOPE
/// RFC822.SIZE INTERNALDATE BODYSTRUCTURE)` response item. `thread_key` is
/// left as a placeholder (`ThreadKey(String::new())`) - callers compute it in
/// bulk across the whole fetched set via
/// `lookout_core::thread::compute_thread_keys`. `BODYSTRUCTURE` rides along
/// so `structure`/`has_attachment` are known without any body fetch; a server
/// that omits it leaves `structure` as `None` and the viewer falls back to a
/// whole-message fetch.
pub fn summary_from_fetch(mailbox: &MailboxId, fetch: &Fetch) -> Option<EmailSummary> {
    let uid = Uid(fetch.uid?);
    let envelope = fetch.envelope()?;

    let subject = envelope.subject.as_ref().map(|c| cow_to_decoded_string(c));
    let message_id = envelope.message_id.as_ref().map(|c| String::from_utf8_lossy(c).trim().to_string());
    let in_reply_to = envelope.in_reply_to.as_ref().map(|c| String::from_utf8_lossy(c).trim().to_string());

    let date = envelope
        .date
        .as_ref()
        .and_then(|d| DateTime::parse_from_rfc2822(String::from_utf8_lossy(d).trim()).ok())
        .map(|d| d.with_timezone(&Utc))
        .or_else(|| fetch.internal_date().map(|d| d.with_timezone(&Utc)))
        .unwrap_or_else(Utc::now);

    let (flags, keywords) = flags_from_fetch(fetch);

    // The selected-header block rides on the envelope fetch
    // (`BODY.PEEK[HEADER.FIELDS (...)]`, see `ENVELOPE_FETCH_ITEMS`): a server
    // that didn't return it (or an older cached fetch) leaves every marker at
    // its default.
    let headers = selected_headers(fetch.header());
    let importance = importance_from_headers(&headers).unwrap_or_default();
    let sensitivity = sensitivity_from_headers(&headers).unwrap_or_default();
    let list_id = header_value(&headers, "List-Id").map(str::trim).filter(|v| !v.is_empty()).map(str::to_string);

    let structure = fetch.bodystructure().map(crate::structure::parts_from_bodystructure);
    let has_attachment = structure.as_ref().map(|p| crate::structure::has_attachments(p)).unwrap_or(false);
    let has_calendar = structure.as_ref().map(|p| crate::structure::has_calendar_parts(p)).unwrap_or(false);

    Some(EmailSummary {
        inference_classification: Default::default(),
        uid,
        mailbox: mailbox.clone(),
        message_id,
        in_reply_to,
        references: Vec::new(), // ENVELOPE has no References; needs a BODY[HEADER.FIELDS (REFERENCES)] fetch (Phase 2).
        thread_key: ThreadKey(String::new()),
        subject,
        from: parse_addresses(&envelope.from),
        to: parse_addresses(&envelope.to),
        cc: parse_addresses(&envelope.cc),
        date,
        flags,
        keywords,
        size: fetch.size.unwrap_or(0),
        has_attachment,
        has_calendar,
        preview: None,   // Requires a body fetch; filled in by `sync_mailbox`'s second phase.
        mentions: false, // Likewise derived from the body; filled in with the preview (M-25).
        importance,
        sensitivity,
        list_id,
        structure,
    })
}

/// Fallback for a server which lists a live UID but does not supply a
/// usable ENVELOPE. Parse actual RFC 5322 headers, without requesting
/// BODYSTRUCTURE or the full MIME payload.
pub(crate) fn summary_from_header_fetch(mailbox: &MailboxId, fetch: &Fetch) -> Option<EmailSummary> {
    let uid = Uid(fetch.uid?);
    let raw = fetch.header()?;
    let (flags, keywords) = flags_from_fetch(fetch);
    header_summary(mailbox, uid, raw, fetch.internal_date().map(|d| d.with_timezone(&Utc)), fetch.size.unwrap_or(0), flags, keywords)
}

fn header_summary(
    mailbox: &MailboxId, uid: Uid, raw: &[u8], internal_date: Option<DateTime<Utc>>,
    size: u32, flags: BTreeSet<SystemFlagBit>, keywords: BTreeSet<String>,
) -> Option<EmailSummary> {
    use mail_parser::{Address, HeaderValue, MessageParser};
    let message = MessageParser::default().parse_headers(raw)?;
    let headers = selected_headers(Some(raw));
    let addresses = |key: &str| -> Vec<EmailAddress> {
        let list: Vec<&mail_parser::Addr<'_>> = match message.header(key) {
            Some(HeaderValue::Address(Address::List(list))) => list.iter().collect(),
            Some(HeaderValue::Address(Address::Group(groups))) => groups.iter().flat_map(|g| g.addresses.iter()).collect(),
            _ => Vec::new(),
        };
        list.into_iter().filter_map(|a| Some(EmailAddress {
            address: a.address.as_deref()?.to_owned(),
            name: a.name.as_deref().filter(|n| !n.trim().is_empty()).map(str::to_owned),
        })).collect()
    };
    let field = |name: &str| header_value(&headers, name).map(str::trim).filter(|v| !v.is_empty()).map(str::to_owned);
    let date = field("Date").and_then(|d| DateTime::parse_from_rfc2822(&d).ok()).map(|d| d.with_timezone(&Utc))
        .or(internal_date).unwrap_or_else(Utc::now);
    Some(EmailSummary {
        inference_classification: Default::default(),
        uid, mailbox: mailbox.clone(),
        message_id: field("Message-ID"), in_reply_to: field("In-Reply-To"),
        references: field("References").map(|r| r.split_whitespace().map(str::to_owned).collect()).unwrap_or_default(),
        thread_key: ThreadKey(String::new()),
        subject: message.subject().map(str::to_owned),
        from: addresses("from"), to: addresses("to"), cc: addresses("cc"),
        date, flags, keywords, size,
        // Unknown structure: the normal full MIME on-demand path will
        // recover attachments and calendar content when opened.
        has_attachment: false, has_calendar: false, structure: None,
        preview: None, mentions: false,
        importance: importance_from_headers(&headers).unwrap_or_default(),
        sensitivity: sensitivity_from_headers(&headers).unwrap_or_default(),
        list_id: field("List-Id"),
    })
}

/// Parses the raw `BODY.PEEK[HEADER.FIELDS (...)]` section the envelope fetch
/// requests alongside the envelope into the `(name, value)` pairs the interop
/// readers expect. Delegates to [`crate::body::parse_headers_section`] (same
/// mail_parser unfolding/trimming), so a section the server didn't return
/// yields an empty list and every marker stays at its default.
fn selected_headers(raw: Option<&[u8]>) -> Vec<(String, String)> {
    raw.map(crate::body::parse_headers_section).unwrap_or_default()
}

/// Parses a fetch response item's `FLAGS` into system flag bits and custom
/// keyword atoms (including the `$Lookout-tag-*` color-tag namespace).
/// Shared by `summary_from_fetch` and `sync_mailbox`'s lightweight
/// flags-only refresh, so both classify flags identically.
pub fn flags_from_fetch(fetch: &Fetch) -> (BTreeSet<SystemFlagBit>, BTreeSet<String>) {
    let mut flags = BTreeSet::new();
    let mut keywords = BTreeSet::new();
    for flag in fetch.flags() {
        let raw = imap_flag_to_string(&flag);
        match SystemFlagBit::from_imap_flag(&raw) {
            Some(bit) => {
                flags.insert(bit);
            }
            None if raw == "\\Recent" => {}
            None => {
                keywords.insert(raw);
            }
        }
    }
    (flags, keywords)
}

fn imap_flag_to_string(flag: &async_imap::types::Flag<'_>) -> String {
    use async_imap::types::Flag;
    match flag {
        Flag::Seen => "\\Seen".to_string(),
        Flag::Answered => "\\Answered".to_string(),
        Flag::Flagged => "\\Flagged".to_string(),
        Flag::Deleted => "\\Deleted".to_string(),
        Flag::Draft => "\\Draft".to_string(),
        Flag::Recent => "\\Recent".to_string(),
        Flag::MayCreate => "\\*".to_string(),
        Flag::Custom(s) => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_fallback_preserves_real_message_metadata() {
        let mailbox = MailboxId::new(&lookout_core::AccountId("test".into()), "INBOX");
        let raw = b"From: Alice <alice@example.test>\r\nTo: Bob <bob@example.test>\r\nSubject: =?UTF-8?Q?Hello_World?=\r\nMessage-ID: <id@example.test>\r\nReferences: <a@example.test> <b@example.test>\r\nDate: Wed, 10 Jun 2026 19:30:00 +0000\r\n\r\n";
        let summary = header_summary(&mailbox, Uid(1570), raw, None, 123, BTreeSet::from([SystemFlagBit::Seen]), BTreeSet::new()).unwrap();
        assert_eq!(summary.uid, Uid(1570));
        assert_eq!(summary.subject.as_deref(), Some("Hello World"));
        assert_eq!(summary.from[0].address, "alice@example.test");
        assert_eq!(summary.to[0].address, "bob@example.test");
        assert_eq!(summary.message_id.as_deref(), Some("<id@example.test>"));
        assert_eq!(summary.references.len(), 2);
        assert!(summary.flags.contains(&SystemFlagBit::Seen));
        assert!(summary.structure.is_none());
    }

    #[test]
    fn decodes_utf8_b_encoded_subject() {
        // "Café ☕" in UTF-8, base64-encoded.
        let encoded = "=?UTF-8?B?Q2Fmw6kg4piV?=";
        assert_eq!(decode_mime_words(encoded), "Café ☕");
    }

    #[test]
    fn decodes_q_encoded_subject_with_underscores_as_spaces() {
        let encoded = "=?UTF-8?Q?Hello_World?=";
        assert_eq!(decode_mime_words(encoded), "Hello World");
    }

    #[test]
    fn leaves_plain_ascii_subject_untouched() {
        assert_eq!(decode_mime_words("Plain subject"), "Plain subject");
    }

    #[test]
    fn decodes_adjacent_encoded_words_without_inserting_fold_whitespace() {
        let encoded = "=?UTF-8?Q?Hello?= =?UTF-8?Q?World?=";
        assert_eq!(decode_mime_words(encoded), "HelloWorld");
    }

    #[test]
    fn decodes_latin1_q_encoded_subject() {
        // "café" in ISO-8859-1: c a f =E9
        let encoded = "=?ISO-8859-1?Q?caf=E9?=";
        assert_eq!(decode_mime_words(encoded), "café");
    }

    #[test]
    fn decodes_legacy_cyrillic_and_japanese_encoded_words() {
        // Synthetic subject, represented in each encoding used by legacy
        // Exchange messages. ISO-2022-JP also has Cyrillic code points.
        for encoded in [
            "=?windows-1251?B?z/Du4uXw6uAg8eL/5+g=?=",
            "=?koi8-r?B?8NLP18XSy8Eg09fR2sk=?=",
            "=?iso-2022-jp?B?GyRCJzEnYidgJ1MnVidiJ1wnURsoQiAbJEInYydTJ3EnWSdaGyhC?=",
        ] {
            assert_eq!(decode_mime_words(encoded), "Проверка связи");
        }
    }

    #[test]
    fn decodes_cyrillic_q_words_and_preserves_prefix() {
        assert_eq!(
            decode_mime_words("Re: =?windows-1251?Q?=CF=F0=E8=E2=E5=F2?="),
            "Re: Привет"
        );
    }

    #[test]
    fn custom_flags_map_to_keyword_atoms() {
        use async_imap::types::Flag;
        // The `summary_from_fetch` keyword path: a `Flag::Custom` atom is
        // rendered verbatim, and since it's not a `SystemFlagBit` (and not
        // `\Recent`) it lands in `EmailSummary::keywords` untouched - which is
        // what lets `$Lookout-tag-*` color tags flow through the envelope
        // fetch into the cache and UI for free.
        assert_eq!(imap_flag_to_string(&Flag::Custom("$Lookout-tag-work".into())), "$Lookout-tag-work");
        assert_eq!(imap_flag_to_string(&Flag::Custom("mykeyword".into())), "mykeyword");
        // System flags still resolve to their bits.
        assert_eq!(SystemFlagBit::from_imap_flag(&imap_flag_to_string(&Flag::Seen)), Some(SystemFlagBit::Seen));
        assert_eq!(SystemFlagBit::from_imap_flag(&imap_flag_to_string(&Flag::Custom("$Lookout-tag-work".into()))), None);
    }

    #[test]
    fn envelope_subject_with_raw_utf8_parses() {
        use async_imap::imap_proto::types::{AttributeValue, Response};
        // A real-world server sending the ENVELOPE subject as raw UTF-8 (no
        // MUTF-7, no RFC 2047 encoding). Before the vendored imap-proto fix
        // (`is_char` accepting 8-bit bytes), the emoji's non-ASCII bytes made
        // `quoted` fail with a `TakeWhile1` error, aborting the whole FETCH
        // response - and with it the session, which reconnected and hit the
        // same message forever. This is the exact response from the field.
        let raw = b"* 4 FETCH (UID 4 FLAGS () ENVELOPE (\"Wed, 10 Jun 2026 19:30:00 +0000\" \"Weekend hike photos \xF0\x9F\x8F\x94\xEF\xB8\x8F\" ((\"Alex Tran\" NIL \"alex.tran\" \"freemail.example\")) ((\"Alex Tran\" NIL \"alex.tran\" \"freemail.example\")) ((\"Alex Tran\" NIL \"alex.tran\" \"freemail.example\")) ((\"Jordan Casey\" NIL \"jordan.casey\" \"freemail.example\")) NIL NIL NIL \"<0003.1786668429@freemail.example>\") RFC822.SIZE 33461 INTERNALDATE \"10-Jun-2026 19:30:00 +0000\" BODYSTRUCTURE ((\"text\" \"plain\" (\"charset\" \"utf-8\") NIL NIL \"quoted-printable\" 212 8 \"b4df2420bff4d3ffcd08ff86388fd986\" NIL NIL NIL)(\"image\" \"jpeg\" NIL NIL NIL \"base64\" 32522 \"c01167c97548255f7311848b616b02bd\" (\"attachment\" (\"filename\" \"summit_view.jpg\")) NIL NIL) \"mixed\" (\"boundary\" \"===============5030118478018109776==\") NIL NIL NIL))\r\n";
        let (remaining, response) = async_imap::imap_proto::parser::parse_response(raw).expect("UTF-8 ENVELOPE subject should parse");
        assert!(remaining.is_empty());
        let Response::Fetch(_, attrs) = response else {
            panic!("expected a FETCH response, got {response:?}");
        };
        let subject = attrs.iter().find_map(|a| match a {
            AttributeValue::Envelope(e) => e.subject.as_ref().map(|s| String::from_utf8_lossy(s).into_owned()),
            _ => None,
        });
        assert_eq!(subject.as_deref(), Some("Weekend hike photos 🏔\u{fe0f}"));
    }

    #[test]
    fn envelope_unescapes_quoted_subject_and_sender_name() {
        use async_imap::imap_proto::types::{AttributeValue, Response};
        // A server quoting a subject and display name that themselves contain
        // double quotes: IMAP escapes each one as `\"`. The parser must return
        // the display text, not the wire escaping.
        let raw = concat!(
            r#"* 5 FETCH (UID 5 FLAGS () ENVELOPE ("Wed, 10 Jun 2026 19:31:00 +0000" "Re: \"Window Positioner\"" (("Ada \"The Countess\" Lovelace" NIL "ada" "example.com")) (("Ada \"The Countess\" Lovelace" NIL "ada" "example.com")) (("Ada \"The Countess\" Lovelace" NIL "ada" "example.com")) (("Jordan Casey" NIL "jordan" "example.com")) NIL NIL NIL "<id@example.com>"))"#,
            "\r\n"
        )
        .as_bytes();
        let (remaining, response) = async_imap::imap_proto::parser::parse_response(raw).expect("escaped ENVELOPE fields should parse");
        assert!(remaining.is_empty());
        let Response::Fetch(_, attrs) = response else {
            panic!("expected a FETCH response, got {response:?}");
        };
        let envelope = attrs
            .iter()
            .find_map(|a| match a {
                AttributeValue::Envelope(e) => Some(e),
                _ => None,
            })
            .expect("FETCH should carry an ENVELOPE");
        let subject = envelope.subject.as_deref().map(|s| std::str::from_utf8(s).unwrap());
        assert_eq!(subject, Some(r#"Re: "Window Positioner""#));
        let sender_name = envelope
            .from
            .as_ref()
            .and_then(|a| a.first())
            .and_then(|a| a.name.as_deref())
            .map(|n| std::str::from_utf8(n).unwrap());
        assert_eq!(sender_name, Some(r#"Ada "The Countess" Lovelace"#));
    }

    #[test]
    fn selected_headers_parse_importance_sensitivity_and_list_id() {
        let raw = b"Importance: High\r\nX-Priority: 1 (Highest)\r\nSensitivity: Private\r\nList-Id: Announcements <announce.example.com>\r\nSubject: ignored\r\n\r\n";
        let headers = selected_headers(Some(raw));
        assert_eq!(importance_from_headers(&headers), Some(lookout_core::Importance::High));
        assert_eq!(sensitivity_from_headers(&headers), Some(lookout_core::MessageSensitivity::Private));
        assert_eq!(header_value(&headers, "List-Id").map(str::trim), Some("Announcements <announce.example.com>"));
    }

    #[test]
    fn selected_headers_unfolds_a_wrapped_field() {
        let raw = b"Authentication-Results: mx.example.com;\r\n spf=pass smtp.mailfrom=a@b\r\nSensitivity: personal\r\n\r\n";
        let headers = selected_headers(Some(raw));
        let auth = header_value(&headers, "Authentication-Results").unwrap();
        assert!(auth.contains("spf=pass"), "unfolded value was {auth:?}");
        assert_eq!(sensitivity_from_headers(&headers), Some(lookout_core::MessageSensitivity::Personal));
    }

    #[test]
    fn selected_headers_absent_defaults_to_normal() {
        let headers = selected_headers(None);
        assert!(headers.is_empty());
        assert_eq!(importance_from_headers(&headers).unwrap_or_default(), lookout_core::Importance::Normal);
        assert_eq!(sensitivity_from_headers(&headers).unwrap_or_default(), lookout_core::MessageSensitivity::Normal);
    }
}
