//! Standalone, privacy-preserving OAB diagnostics. Compile with rustc.
#[path = "../crates/app/src/oab_decode.rs"]
mod oab_decode;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os().nth(1).ok_or("usage: oab-inspect full.oab")?;
    let bytes = std::fs::read(path)?;
    let book = oab_decode::decode(&bytes)?;
    println!("Serial: 0x{:08x}", book.serial);
    println!("Declared records: {}", book.declared_records);
    println!("Decoded records: {}", book.contacts.len());
    println!("SMTP addresses: {}", book.contacts.iter().filter(|c| !c.smtp.is_empty()).count());
    println!("Display names: {}", book.contacts.iter().filter(|c| !c.display_name.is_empty()).count());
    let mut types = std::collections::BTreeMap::new();
    for c in &book.contacts { *types.entry(c.object_type).or_insert(0usize) += 1; }
    println!("Object type counts: {types:?}");
    println!("Property presence counts:");
    for tag in book.properties {
        println!("0x{tag:08X}: {}", book.present_counts.get(&tag).copied().unwrap_or(0));
    }
    Ok(())
}
