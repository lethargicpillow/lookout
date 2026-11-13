//! Exchange OAB v4 Full Details decoder (MS-OXOAB 2.9).
//! No GTK, network, credentials or filesystem dependencies. Strings in OAB
//! v4 are NUL-terminated UTF-8, not the UTF-16LE used by ordinary MAPI.
use std::collections::BTreeMap;

type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Contact {
    pub legacy_dn: String,
    pub smtp: String,
    pub display_name: String,
    pub given_name: String,
    pub surname: String,
    pub company: String,
    pub department: String,
    pub title: String,
    pub office: String,
    pub business_phone: String,
    pub mobile_phone: String,
    pub object_type: Option<u32>,
    pub display_type: Option<u32>,
}

#[derive(Debug)]
pub struct Book {
    pub serial: u32,
    pub declared_records: u32,
    pub properties: Vec<u32>,
    pub contacts: Vec<Contact>,
    pub present_counts: BTreeMap<u32, usize>,
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, pos: 0 } }
    fn remaining(&self) -> usize { self.bytes.len() - self.pos }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or("offset overflow")?;
        let result = self.bytes.get(self.pos..end).ok_or("truncated OAB data")?;
        self.pos = end;
        Ok(result)
    }
    fn byte(&mut self) -> Result<u8> { Ok(self.take(1)?[0]) }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn packed_int(&mut self) -> Result<u32> {
        let first = self.byte()?;
        if first < 0x80 { return Ok(first as u32); }
        let n = (first & 0x7f) as usize;
        if !(1..=4).contains(&n) { return Err("invalid packed integer length".into()); }
        let mut raw = [0u8; 4];
        raw[..n].copy_from_slice(self.take(n)?);
        Ok(u32::from_le_bytes(raw))
    }
    fn string(&mut self) -> Result<&'a [u8]> {
        let len = self.bytes[self.pos..].iter().position(|b| *b == 0)
            .ok_or("unterminated OAB string")?;
        let value = self.take(len)?;
        self.take(1)?;
        Ok(value)
    }
    fn block(&mut self) -> Result<Reader<'a>> {
        let size = self.u32()? as usize;
        let payload = size.checked_sub(4).ok_or("invalid OAB block size")?;
        Ok(Reader::new(self.take(payload)?))
    }
    fn finish(&self) -> Result<()> {
        if self.remaining() == 0 { Ok(()) } else {
            Err(format!("{} unconsumed bytes", self.remaining()))
        }
    }
}

fn schema(reader: &mut Reader<'_>) -> Result<Vec<u32>> {
    let count = reader.u32()? as usize;
    if count > reader.remaining() / 8 { return Err("truncated property table".into()); }
    let mut tags = Vec::with_capacity(count);
    for _ in 0..count {
        let tag = reader.u32()?;
        reader.u32()?; // index flags, not part of the property type
        tags.push(tag);
    }
    Ok(tags)
}

enum Value<'a> { Text(&'a [u8]), Integer(u32), Other }

fn scalar<'a>(reader: &mut Reader<'a>, ty: u16) -> Result<Value<'a>> {
    match ty {
        0x0003 => Ok(Value::Integer(reader.packed_int()?)),
        0x000b => {
            if reader.byte()? > 1 { return Err("invalid OAB boolean".into()); }
            Ok(Value::Other)
        }
        0x001e | 0x001f => Ok(Value::Text(reader.string()?)),
        0x0102 => {
            let length = reader.packed_int()? as usize;
            reader.take(length)?;
            Ok(Value::Other)
        }
        0x000d => Err("PtypObject cannot have an offline value".into()),
        _ => Err(format!("unsupported OAB property type 0x{ty:04x}")),
    }
}

fn value<'a>(reader: &mut Reader<'a>, ty: u16) -> Result<Value<'a>> {
    match ty {
        0x1003 | 0x101e | 0x101f | 0x1102 => {
            let count = reader.packed_int()? as usize;
            // Every scalar occupies at least one byte. Bound work by record size.
            if count > reader.remaining() { return Err("invalid multi-value count".into()); }
            for _ in 0..count { scalar(reader, ty & !0x1000)?; }
            Ok(Value::Other)
        }
        _ => scalar(reader, ty),
    }
}

fn record(reader: &mut Reader<'_>, tags: &[u32], mut visit: impl FnMut(u32, Value<'_>) -> Result<()>) -> Result<()> {
    let mut block = reader.block()?;
    let bits = block.take(tags.len().div_ceil(8))?;
    for (i, tag) in tags.iter().copied().enumerate() {
        if bits[i / 8] & (0x80 >> (i % 8)) != 0 {
            let val = value(&mut block, tag as u16)
                .map_err(|e| format!("property 0x{tag:08x}: {e}"))?;
            visit(tag, val)?;
        }
    }
    block.finish()
}

fn contact_value(contact: &mut Contact, tag: u32, val: Value<'_>) -> Result<()> {
    match val {
        Value::Text(bytes) => {
            let field = match tag >> 16 {
                0x3003 => &mut contact.legacy_dn,
                0x39fe => &mut contact.smtp,
                0x3001 => &mut contact.display_name,
                0x3a06 => &mut contact.given_name,
                0x3a11 => &mut contact.surname,
                0x3a16 => &mut contact.company,
                0x3a18 => &mut contact.department,
                0x3a17 => &mut contact.title,
                0x3a19 => &mut contact.office,
                0x3a08 => &mut contact.business_phone,
                0x3a1c => &mut contact.mobile_phone,
                _ => return Ok(()),
            };
            *field = std::str::from_utf8(bytes).map_err(|_| format!("invalid UTF-8 for 0x{tag:08x}"))?.to_owned();
        }
        Value::Integer(n) => match tag >> 16 {
            0x0ffe => contact.object_type = Some(n),
            0x3900 => contact.display_type = Some(n),
            _ => {}
        },
        Value::Other => {}
    }
    Ok(())
}

/// Decode every record, including objects with no SMTP address. Do not publish
/// partial results on a malformed file: the caller can retain the prior cache.
pub fn decode(bytes: &[u8]) -> Result<Book> {
    let mut reader = Reader::new(bytes);
    let version = reader.u32()?;
    if version != 0x20 { return Err(format!("unsupported OAB version 0x{version:08x}")); }
    let serial = reader.u32()?;
    let declared_records = reader.u32()?;
    let mut metadata = reader.block()?;
    let header_tags = schema(&mut metadata)?;
    let properties = schema(&mut metadata)?;
    metadata.finish()?;
    record(&mut reader, &header_tags, |_, _| Ok(())).map_err(|e| format!("OAB header: {e}"))?;
    if declared_records as usize > reader.remaining() / 4 {
        return Err("record count exceeds remaining data".into());
    }
    let mut contacts = Vec::with_capacity(declared_records as usize);
    let mut present_counts = BTreeMap::new();
    for index in 0..declared_records {
        let mut contact = Contact::default();
        let offset = reader.pos;
        record(&mut reader, &properties, |tag, val| {
            *present_counts.entry(tag).or_insert(0) += 1;
            contact_value(&mut contact, tag, val)
        }).map_err(|e| format!("record {index} at byte {offset}: {e}"))?;
        contacts.push(contact);
    }
    reader.finish()?;
    Ok(Book { serial, declared_records, properties, contacts, present_counts })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn u32le(out: &mut Vec<u8>, n: u32) { out.extend(n.to_le_bytes()); }
    fn block(out: &mut Vec<u8>, data: &[u8]) {
        u32le(out, (4 + data.len()) as u32);
        out.extend(data);
    }
    fn sample() -> Vec<u8> {
        let tags = [0x3003001e, 0x39fe001f, 0x3001001f, 0x8cac101f,
            0x8c6a1102, 0x0ffe0003, 0x8cdb000d, 0x39000003, 0x3a40000b,
            0x68051003];
        let mut bytes = Vec::new();
        for n in [0x20, 42, 1] { u32le(&mut bytes, n); }
        let mut meta = Vec::new();
        u32le(&mut meta, 1);
        u32le(&mut meta, 0x6800001f);
        u32le(&mut meta, 0);
        u32le(&mut meta, tags.len() as u32);
        for tag in tags { u32le(&mut meta, tag); u32le(&mut meta, 0); }
        block(&mut bytes, &meta);
        block(&mut bytes, b"\x80GAL\0");
        let mut contact = vec![0xfd, 0xc0]; // object property absent, others present
        contact.extend(b"/o=test/cn=user\0user@example.invalid\0");
        contact.extend("Иван Тестов\0".as_bytes());
        contact.extend(b"\x02one\0two\0");
        contact.extend([1, 3, 0, 1, 2]); // one binary array element, 3 bytes
        contact.extend([6, 0, 1, 2, 0x81, 0x80, 0x82, 0x00, 0x01]);
        block(&mut bytes, &contact);
        bytes
    }
    #[test]
    fn decodes_unicode_and_skips_multiple_values_and_absent_objects() {
        let book = decode(&sample()).unwrap();
        assert_eq!(book.contacts.len(), 1);
        assert_eq!(book.contacts[0].display_name, "Иван Тестов");
        assert_eq!(book.contacts[0].smtp, "user@example.invalid");
        assert_eq!(book.contacts[0].object_type, Some(6));
        assert_eq!(book.contacts[0].display_type, Some(0));
        assert_eq!(book.present_counts.get(&0x8cdb000d), None);
    }
    #[test]
    fn refuses_truncation_and_trailing_data() {
        let bytes = sample();
        for i in 0..bytes.len() { assert!(decode(&bytes[..i]).is_err(), "cut {i}"); }
        let mut extra = bytes;
        extra.push(0);
        assert!(decode(&extra).is_err());
    }
    #[test]
    fn packed_integer_boundaries() {
        let mut r = Reader::new(&[0x7f, 0x81, 0x80, 0x82, 0, 1, 0x84, 0xff, 0xff, 0xff, 0xff]);
        for n in [127, 128, 256, u32::MAX] { assert_eq!(r.packed_int().unwrap(), n); }
        assert!(Reader::new(&[0x85]).packed_int().is_err());
    }
}
