//! Minimal WinpkFilter static filter table helpers shared with diskless_passthrough.
//!
//! The SDK does not install IPv6 block filters itself (the interceptor disables
//! IPv6 via PowerShell instead), but the diskless pass-through module needs to
//! read and write the table so it can insert / remove kernel PASS entries without
//! disturbing anything already in the table.

#[cfg(target_os = "windows")]
use ndisapi::StaticFilterTable;
#[cfg(any(test, target_os = "windows"))]
use ndisapi::StaticFilter;

/// Generous upper bound for reading/merging the driver's static filter table.
pub(crate) const STATIC_FILTER_TABLE_CAPACITY: usize = 256;

/// Read the driver's current static filter table as owned entries.
#[cfg(target_os = "windows")]
pub(crate) fn read_static_filter_entries(
    driver: &ndisapi::Ndisapi,
) -> Result<Vec<StaticFilter>, String> {
    let size = driver
        .get_packet_filter_table_size()
        .map_err(|e| format!("Failed to query WinpkFilter static filter table size: {e}"))?;
    if size == 0 {
        return Ok(Vec::new());
    }
    if size > STATIC_FILTER_TABLE_CAPACITY {
        return Err(format!(
            "WinpkFilter static filter table has {size} entries, more than the supported {STATIC_FILTER_TABLE_CAPACITY}"
        ));
    }

    let mut table = Box::new(StaticFilterTable::<STATIC_FILTER_TABLE_CAPACITY>::new());
    driver
        .get_packet_filter_table(table.as_mut())
        .map_err(|e| format!("Failed to read WinpkFilter static filter table: {e}"))?;

    let count = (table.table_size as usize).min(STATIC_FILTER_TABLE_CAPACITY);
    let base = std::ptr::addr_of!(table.static_filters).cast::<StaticFilter>();
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        // SAFETY: i < count <= capacity; unaligned read because the table is
        // repr(C, packed).
        entries.push(unsafe { base.add(i).read_unaligned() });
    }
    Ok(entries)
}

/// Replace the driver's static filter table with exactly `entries`.
#[cfg(target_os = "windows")]
pub(crate) fn set_static_filter_entries(
    driver: &ndisapi::Ndisapi,
    entries: &[StaticFilter],
) -> Result<(), String> {
    if entries.len() > STATIC_FILTER_TABLE_CAPACITY {
        return Err(format!(
            "Refusing to write {} WinpkFilter static filter entries, more than the supported {STATIC_FILTER_TABLE_CAPACITY}",
            entries.len()
        ));
    }

    let mut table = Box::new(StaticFilterTable::<STATIC_FILTER_TABLE_CAPACITY>::new());
    table.table_size = entries.len() as u32;
    let base = std::ptr::addr_of_mut!(table.static_filters).cast::<StaticFilter>();
    for (i, entry) in entries.iter().enumerate() {
        // SAFETY: i < entries.len() <= capacity; unaligned write because the
        // table is repr(C, packed).
        unsafe { base.add(i).write_unaligned(*entry) };
    }
    driver
        .set_packet_filter_table(table.as_ref())
        .map_err(|e| format!("Failed to write WinpkFilter static filter table: {e}"))
}
