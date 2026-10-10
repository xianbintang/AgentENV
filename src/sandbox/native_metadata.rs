//! Typed immutable metadata from authenticated native receipts.
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Write;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeFileVersion {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub mtime_seconds: i64,
    pub mtime_nanos: u32,
    pub ctime_seconds: i64,
    pub ctime_nanos: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeFileTime {
    pub seconds: i64,
    pub nanos: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeFileType {
    File,
    Directory,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeFileEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: NativeFileType,
    pub path: String,
    pub size: u64,
    pub mode: u32,
    pub permissions: String,
    pub owner: String,
    pub group: String,
    pub modified_time: NativeFileTime,
    pub symlink_target: Option<String>,
    pub version: NativeFileVersion,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeStatReceipt {
    pub path: String,
    pub entry: Option<NativeFileEntry>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeListSummary {
    pub path: String,
    pub count: u64,
    pub snapshot_sha256: String,
    pub version: NativeFileVersion,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeListPage {
    pub path: String,
    pub cursor: u64,
    pub next_cursor: u64,
    pub count: u64,
    pub entries: Vec<NativeFileEntry>,
    pub snapshot_sha256: String,
    pub version: NativeFileVersion,
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NativeMetadataReceipt {
    FileStatResult(NativeStatReceipt),
    MakeDirResult(NativeStatReceipt),
    ListPage(NativeListPage),
    ListResult(NativeListSummary),
}

pub(crate) fn path(path: &str) -> Result<()> {
    if path == "." {
        return Ok(());
    }
    if path.is_empty()
        || path.len() > 512
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains('\0')
        || path.split('/').count() > 16
        || path
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == ".." || c.len() > 64)
    {
        bail!("native metadata path");
    }
    Ok(())
}
fn version(v: &NativeFileVersion) -> Result<()> {
    if v.size > 33554432 || v.mtime_nanos >= 1_000_000_000 || v.ctime_nanos >= 1_000_000_000 {
        bail!("native metadata version");
    }
    Ok(())
}
fn permissions(mode: u32) -> String {
    let mut chars = ['-'; 9];
    for (i, bit) in [
        0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001,
    ]
    .iter()
    .enumerate()
    {
        if mode & bit != 0 {
            chars[i] = ['r', 'w', 'x'][i % 3];
        }
    }
    for (i, bit, yes, no) in [
        (2, 0o4000, 's', 'S'),
        (5, 0o2000, 's', 'S'),
        (8, 0o1000, 't', 'T'),
    ] {
        if mode & bit != 0 {
            chars[i] = if chars[i] == 'x' { yes } else { no };
        }
    }
    chars.iter().collect()
}
fn entry(e: &NativeFileEntry) -> Result<()> {
    path(&e.path)?;
    version(&e.version)?;
    if e.name.is_empty()
        || e.name.len() > 64
        || e.name.contains('/')
        || e.name.contains('\\')
        || e.name.contains('\0')
        || matches!(e.name.as_str(), "." | "..")
        || (e.path != "." && e.path.rsplit('/').next() != Some(e.name.as_str()))
        || e.size != e.version.size
        || e.modified_time.seconds != e.version.mtime_seconds
        || e.modified_time.nanos != e.version.mtime_nanos
        || e.owner != "1000"
        || e.group != "1000"
        || e.symlink_target.is_some()
        || e.mode > 0o177777
        || e.permissions != permissions(e.mode)
        || !matches!(
            (&e.kind, e.mode & 0o170000),
            (NativeFileType::File, 0o100000) | (NativeFileType::Directory, 0o040000)
        )
    {
        bail!("native metadata entry");
    }
    Ok(())
}
fn summary(s: &NativeListSummary) -> Result<()> {
    path(&s.path)?;
    version(&s.version)?;
    if s.count > 512
        || s.snapshot_sha256.len() != 64
        || !s
            .snapshot_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("native metadata summary");
    }
    Ok(())
}
const LIST_BUDGET: usize = 512 * 1024;
// Includes the one incoming Value, typed page, and one canonical entry temporary.
const PAGE_TEMP: usize = 160 * 1024;
struct HashWriter {
    hash: Sha256,
    bytes: usize,
}
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.hash.update(bytes);
        self.bytes += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn canonical_digest(entries: &[NativeFileEntry]) -> Result<String> {
    let mut sink = HashWriter {
        hash: Sha256::new(),
        bytes: 0,
    };
    sink.write_all(b"[")?;
    for (i, entry) in entries.iter().enumerate() {
        if i != 0 {
            sink.write_all(b",")?;
        }
        // Canonical guest key order is independent of SDK preserve_order features.
        // Recursively sort only this bounded entry, never a whole-list Value.
        let mut value = serde_json::to_value(entry)?;
        value.sort_all_objects();
        serde_json::to_writer(&mut sink, &value)?;
    }
    sink.write_all(b"]")?;
    Ok(format!("{:x}", sink.hash.finalize()))
}
fn entry_strings(e: &NativeFileEntry) -> usize {
    e.name.capacity()
        + e.path.capacity()
        + e.permissions.capacity()
        + e.owner.capacity()
        + e.group.capacity()
        + e.symlink_target.as_ref().map_or(0, String::capacity)
}
fn value_bytes(v: &Value) -> usize {
    std::mem::size_of::<Value>()
        + match v {
            Value::String(s) => s.capacity(),
            Value::Array(a) => {
                a.capacity() * std::mem::size_of::<Value>()
                    + a.iter().map(value_bytes).sum::<usize>()
            }
            Value::Object(o) => o
                .iter()
                .map(|(k, v)| k.capacity() + 64 + value_bytes(v))
                .sum::<usize>(),
            _ => 0,
        }
}
#[derive(Default)]
pub(crate) struct MetadataCache {
    pub(crate) receipt: Option<NativeMetadataReceipt>,
    summary: Option<NativeListSummary>,
    entries: Vec<NativeFileEntry>,
    // One typed entry cache; fingerprints and boundaries replace full JSON page copies.
    pages: Vec<(u64, u64, [u8; 32])>,
    pub(crate) complete: bool,
}
impl MetadataCache {
    pub(crate) fn new(list: bool) -> Result<Self> {
        let mut cache = Self::default();
        if list {
            cache.entries.try_reserve_exact(512)?;
            cache.pages.try_reserve_exact(512)?;
            if cache.entries.capacity() != 512 || cache.pages.capacity() != 512 {
                bail!("native metadata capacity");
            }
        }
        Ok(cache)
    }
    fn retained_bytes(&self) -> usize {
        self.entries.capacity() * std::mem::size_of::<NativeFileEntry>()
            + self.pages.capacity() * std::mem::size_of::<(u64, u64, [u8; 32])>()
            + self.entries.iter().map(entry_strings).sum::<usize>()
            + 8192
    }
    pub(crate) fn boundary(&self, cursor: u64) -> bool {
        cursor == 0
            || cursor == self.entries.len() as u64
            || self.pages.iter().any(|p| p.0 == cursor)
    }
    pub(crate) fn retain(
        &mut self,
        request_kind: &str,
        request_path: &str,
        kind: &str,
        payload: &Value,
    ) -> Result<()> {
        let mut sink = HashWriter {
            hash: Sha256::new(),
            bytes: 0,
        };
        serde_json::to_writer(&mut sink, payload)?;
        let wire_len = sink.bytes;
        if wire_len > 65536 {
            bail!("native metadata frame");
        }
        if matches!(kind, "file_stat_result" | "make_dir_result") {
            if !matches!(
                (request_kind, kind),
                ("file_stat", "file_stat_result") | ("make_dir", "make_dir_result")
            ) || wire_len > 8192
            {
                bail!("native metadata receipt kind");
            }
            let r: NativeStatReceipt = Deserialize::deserialize(payload)?;
            if r.path != request_path {
                bail!("native metadata receipt path");
            }
            if let Some(e) = &r.entry {
                entry(e)?;
                if e.path != r.path {
                    bail!("native metadata entry path");
                }
            }
            if kind == "make_dir_result"
                && !r
                    .entry
                    .as_ref()
                    .is_some_and(|e| e.kind == NativeFileType::Directory)
            {
                bail!("native mkdir receipt");
            }
            let next = if kind == "file_stat_result" {
                NativeMetadataReceipt::FileStatResult(r)
            } else {
                NativeMetadataReceipt::MakeDirResult(r)
            };
            if self.receipt.as_ref().is_some_and(|old| {
                serde_json::to_value(old).ok() != serde_json::to_value(&next).ok()
            }) {
                bail!("native metadata receipt drift");
            }
            self.receipt = Some(next);
            self.complete = true;
            return Ok(());
        }
        if request_kind != "list_begin" {
            bail!("native metadata list kind");
        }
        if self.entries.capacity() == 0 {
            self.entries.try_reserve_exact(512)?;
            self.pages.try_reserve_exact(512)?;
        }
        if self.entries.capacity() != 512 || self.pages.capacity() != 512 {
            bail!("native metadata capacity");
        }
        if self.retained_bytes() + PAGE_TEMP > LIST_BUDGET || value_bytes(payload) > 96 * 1024 {
            bail!("native metadata transient budget");
        }
        let s = if kind == "list_result" {
            NativeListSummary::deserialize(payload)?
        } else if kind == "list_page" {
            let p: NativeListPage = Deserialize::deserialize(payload)?;
            let s = NativeListSummary {
                path: p.path.clone(),
                count: p.count,
                snapshot_sha256: p.snapshot_sha256.clone(),
                version: p.version.clone(),
            };
            summary(&s)?;
            if p.entries.len() > 64
                || p.next_cursor != p.cursor + p.entries.len() as u64
                || p.next_cursor > p.count
                || (p.count > 0 && p.entries.is_empty())
            {
                bail!("native metadata page range");
            }
            let fp: [u8; 32] = sink.hash.finalize().into();
            if let Some(old) = self.pages.iter().find(|old| old.0 == p.cursor) {
                if *old != (p.cursor, p.next_cursor, fp) {
                    bail!("native metadata page drift");
                }
            } else {
                if p.cursor != self.entries.len() as u64 {
                    bail!("native metadata page gap");
                }
                let mut previous = self.entries.last().map(|e| e.name.as_str());
                for e in &p.entries {
                    entry(e)?;
                    let expected = if p.path == "." {
                        e.name.clone()
                    } else {
                        format!("{}/{}", p.path, e.name)
                    };
                    if e.path != expected || previous.is_some_and(|old| old >= e.name.as_str()) {
                        bail!("native metadata page order");
                    }
                    previous = Some(&e.name);
                }
                let prospective = self.retained_bytes()
                    + p.entries.iter().map(entry_strings).sum::<usize>()
                    + PAGE_TEMP;
                if prospective > LIST_BUDGET
                    || p.entries.capacity() > 64
                    || self.entries.len() + p.entries.len() > 512
                    || self.pages.len() >= 512
                {
                    bail!("native metadata cache budget");
                }
                // Check immutable summary before installing any new retained bytes.
                if self.summary.as_ref().is_some_and(|old| old != &s) {
                    bail!("native metadata summary drift");
                }
                self.entries.extend(p.entries);
                self.pages.push((p.cursor, p.next_cursor, fp));
            }
            s
        } else {
            bail!("native metadata event kind");
        };
        summary(&s)?;
        if s.path != request_path || self.summary.as_ref().is_some_and(|old| old != &s) {
            bail!("native metadata summary drift");
        }
        self.summary = Some(s.clone());
        if kind == "list_result" {
            self.receipt = Some(NativeMetadataReceipt::ListResult(s.clone()));
        }
        if self.entries.len() as u64 == s.count
            && matches!(self.receipt, Some(NativeMetadataReceipt::ListResult(_)))
        {
            if canonical_digest(&self.entries)? != s.snapshot_sha256 {
                bail!("native metadata full digest");
            }
            self.complete = true;
        }
        Ok(())
    }
    pub(crate) fn page(&self, cursor: u64) -> Result<NativeListPage> {
        let s = self
            .summary
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("native list unobserved"))?;
        let (_, end, _) = self
            .pages
            .iter()
            .find(|p| p.0 == cursor)
            .ok_or_else(|| anyhow::anyhow!("native list boundary"))?;
        Ok(NativeListPage {
            path: s.path.clone(),
            cursor,
            next_cursor: *end,
            count: s.count,
            entries: self.entries[cursor as usize..*end as usize].to_vec(),
            snapshot_sha256: s.snapshot_sha256.clone(),
            version: s.version.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn version_fixture() -> NativeFileVersion {
        NativeFileVersion {
            device: 1,
            inode: 2,
            size: 0,
            mtime_seconds: 0,
            mtime_nanos: 0,
            ctime_seconds: 0,
            ctime_nanos: 0,
        }
    }
    fn entry_fixture(name: &str) -> NativeFileEntry {
        NativeFileEntry {
            name: name.into(),
            kind: NativeFileType::File,
            path: name.into(),
            size: 0,
            mode: 0o100600,
            permissions: "rw-------".into(),
            owner: "1000".into(),
            group: "1000".into(),
            modified_time: NativeFileTime {
                seconds: 0,
                nanos: 0,
            },
            symlink_target: None,
            version: version_fixture(),
        }
    }
    fn digest(entries: &[NativeFileEntry]) -> String {
        // Independent test oracle: rebuild object order through BTreeMap, not the
        // production in-place sorter. The fixed literal cross-serializer test is
        // the external anchor for this oracle.
        fn lexical(value: Value) -> Value {
            match value {
                Value::Object(map) => {
                    let sorted: std::collections::BTreeMap<_, _> = map
                        .into_iter()
                        .map(|(key, value)| (key, lexical(value)))
                        .collect();
                    Value::Object(sorted.into_iter().collect())
                }
                Value::Array(values) => Value::Array(values.into_iter().map(lexical).collect()),
                value => value,
            }
        }
        let value = lexical(serde_json::to_value(entries).unwrap());
        format!("{:x}", Sha256::digest(serde_json::to_vec(&value).unwrap()))
    }
    #[test]
    fn metadata_guest_lexicographic_wire_digest_survives_sdk_map_features() {
        // Exact guest canonical bytes: object keys are lexicographic at every level.
        // Expected SHA deliberately does not use SDK typed serialization or digest().
        let guest_array = br#"[{"group":"1000","mode":33152,"modified_time":{"nanos":0,"seconds":0},"name":"a","owner":"1000","path":"a","permissions":"rw-------","size":0,"symlink_target":null,"type":"file","version":{"ctime_nanos":0,"ctime_seconds":0,"device":1,"inode":2,"mtime_nanos":0,"mtime_seconds":0,"size":0}}]"#;
        let expected = format!("{:x}", Sha256::digest(guest_array));
        let entries: Vec<NativeFileEntry> = serde_json::from_slice(guest_array).unwrap();
        assert_eq!(entries, vec![entry_fixture("a")]);
        let summary = NativeListSummary {
            path: ".".into(),
            count: 1,
            snapshot_sha256: expected.clone(),
            version: version_fixture(),
        };
        let page = NativeListPage {
            path: ".".into(),
            cursor: 0,
            next_cursor: 1,
            count: 1,
            entries,
            snapshot_sha256: expected,
            version: version_fixture(),
        };
        let mut cache = MetadataCache::default();
        cache
            .retain(
                "list_begin",
                ".",
                "list_result",
                &serde_json::to_value(&summary).unwrap(),
            )
            .unwrap();
        assert!(!cache.complete);
        cache
            .retain(
                "list_begin",
                ".",
                "list_page",
                &serde_json::to_value(&page).unwrap(),
            )
            .expect(
                "actual guest canonical digest must validate independently of SDK serde features",
            );
        assert!(cache.complete);
        assert_eq!(cache.entries, vec![entry_fixture("a")]);
        assert_eq!(cache.summary, Some(summary));
    }
    #[test]
    fn metadata_early_summary_requires_all_pages_and_full_digest() {
        let entries = vec![entry_fixture("a"), entry_fixture("b")];
        let s = NativeListSummary {
            path: ".".into(),
            count: 2,
            snapshot_sha256: digest(&entries),
            version: version_fixture(),
        };
        let mut cache = MetadataCache::default();
        cache
            .retain(
                "list_begin",
                ".",
                "list_result",
                &serde_json::to_value(&s).unwrap(),
            )
            .unwrap();
        assert!(!cache.complete);
        for i in 0..2 {
            let p = NativeListPage {
                path: ".".into(),
                cursor: i,
                next_cursor: i + 1,
                count: 2,
                entries: vec![entries[i as usize].clone()],
                snapshot_sha256: s.snapshot_sha256.clone(),
                version: s.version.clone(),
            };
            let p = serde_json::to_value(p).unwrap();
            cache.retain("list_begin", ".", "list_page", &p).unwrap();
            cache.retain("list_begin", ".", "list_page", &p).unwrap();
            assert_eq!(cache.complete, i == 1);
        }
        assert!(!cache.boundary(3));
        assert_eq!(cache.entries.len(), 2);
    }
    #[test]
    fn metadata_empty_list_requires_signed_summary_and_exact_empty_digest() {
        let s = NativeListSummary {
            path: ".".into(),
            count: 0,
            snapshot_sha256: digest(&[]),
            version: version_fixture(),
        };
        let p = NativeListPage {
            path: ".".into(),
            cursor: 0,
            next_cursor: 0,
            count: 0,
            entries: vec![],
            snapshot_sha256: s.snapshot_sha256.clone(),
            version: s.version.clone(),
        };
        let mut cache = MetadataCache::default();
        cache
            .retain(
                "list_begin",
                ".",
                "list_page",
                &serde_json::to_value(p).unwrap(),
            )
            .unwrap();
        assert!(!cache.complete);
        cache
            .retain(
                "list_begin",
                ".",
                "list_result",
                &serde_json::to_value(s).unwrap(),
            )
            .unwrap();
        assert!(cache.complete);
    }
    #[test]
    fn metadata_page_gap_cross_sort_drift_and_wrong_full_digest_refuse() {
        let e = entry_fixture("b");
        let mut p = NativeListPage {
            path: ".".into(),
            cursor: 1,
            next_cursor: 2,
            count: 2,
            entries: vec![e],
            snapshot_sha256: "0".repeat(64),
            version: version_fixture(),
        };
        let mut cache = MetadataCache::default();
        assert!(cache
            .retain(
                "list_begin",
                ".",
                "list_page",
                &serde_json::to_value(&p).unwrap()
            )
            .is_err());
        p.cursor = 0;
        p.next_cursor = 1;
        cache
            .retain(
                "list_begin",
                ".",
                "list_page",
                &serde_json::to_value(&p).unwrap(),
            )
            .unwrap();
        let mut drift = p.clone();
        drift.entries[0].version.inode = 3;
        assert!(cache
            .retain(
                "list_begin",
                ".",
                "list_page",
                &serde_json::to_value(drift).unwrap()
            )
            .is_err());
        p.cursor = 1;
        p.next_cursor = 2;
        p.entries = vec![entry_fixture("a")];
        assert!(cache
            .retain(
                "list_begin",
                ".",
                "list_page",
                &serde_json::to_value(&p).unwrap()
            )
            .is_err());
        assert!(!cache.complete);
        p.entries = vec![entry_fixture("c")];
        cache
            .retain(
                "list_begin",
                ".",
                "list_page",
                &serde_json::to_value(&p).unwrap(),
            )
            .unwrap();
        let s = NativeListSummary {
            path: p.path,
            count: 2,
            snapshot_sha256: p.snapshot_sha256,
            version: p.version,
        };
        assert!(cache
            .retain(
                "list_begin",
                ".",
                "list_result",
                &serde_json::to_value(s).unwrap()
            )
            .is_err());
        assert!(!cache.complete);
    }
    #[test]
    fn metadata_long_path_multipage_stream_hash_and_capacity_are_bounded() {
        let root = std::iter::repeat_n("r".repeat(62), 7)
            .collect::<Vec<_>>()
            .join("/");
        let entries: Vec<_> = (0..256)
            .map(|i| {
                let mut e = entry_fixture(&format!("{i:04}{}", "x".repeat(60)));
                e.path = format!("{root}/{}", e.name);
                e
            })
            .collect();
        let expected = digest(&entries);
        assert_eq!(canonical_digest(&entries).unwrap(), expected);
        let summary = NativeListSummary {
            path: root.clone(),
            count: 256,
            snapshot_sha256: expected.clone(),
            version: version_fixture(),
        };
        let mut cache = MetadataCache::new(true).unwrap();
        for (i, part) in entries.chunks(2).enumerate() {
            let p = NativeListPage {
                path: root.clone(),
                cursor: (i * 2) as u64,
                next_cursor: (i * 2 + part.len()) as u64,
                count: 256,
                entries: part.to_vec(),
                snapshot_sha256: expected.clone(),
                version: version_fixture(),
            };
            cache
                .retain(
                    "list_begin",
                    &root,
                    "list_page",
                    &serde_json::to_value(p).unwrap(),
                )
                .unwrap();
            assert!(cache.retained_bytes() + PAGE_TEMP <= LIST_BUDGET);
            assert_eq!(cache.entries.capacity(), 512);
            assert_eq!(cache.pages.capacity(), 512);
        }
        cache
            .retain(
                "list_begin",
                &root,
                "list_result",
                &serde_json::to_value(summary).unwrap(),
            )
            .unwrap();
        assert!(cache.complete);
        let mut oversized = MetadataCache::new(true).unwrap();
        let mut refused = false;
        for i in 0..512 {
            let mut e = entry_fixture(&format!("{i:04}{}", "x".repeat(60)));
            e.path = format!("{root}/{}", e.name);
            let p = NativeListPage {
                path: root.clone(),
                cursor: i,
                next_cursor: i + 1,
                count: 512,
                entries: vec![e],
                snapshot_sha256: "0".repeat(64),
                version: version_fixture(),
            };
            let before = oversized.entries.len();
            if oversized
                .retain(
                    "list_begin",
                    &root,
                    "list_page",
                    &serde_json::to_value(p).unwrap(),
                )
                .is_err()
            {
                assert_eq!(oversized.entries.len(), before);
                refused = true;
                break;
            }
        }
        assert!(refused && !oversized.complete);
        assert!(oversized.retained_bytes() + PAGE_TEMP <= LIST_BUDGET);
    }
    #[test]
    fn metadata_stat_mkdir_validate_actual_type_mode_owner_and_original_path() {
        let mut e = entry_fixture("a");
        let r = NativeStatReceipt {
            path: "a".into(),
            entry: Some(e.clone()),
        };
        assert!(MetadataCache::default()
            .retain(
                "make_dir",
                "a",
                "make_dir_result",
                &serde_json::to_value(&r).unwrap()
            )
            .is_err());
        for field in ["owner", "permissions", "path"] {
            let mut v = serde_json::to_value(&r).unwrap();
            v["entry"][field] = Value::String("foreign".into());
            assert!(MetadataCache::default()
                .retain("file_stat", "a", "file_stat_result", &v)
                .is_err());
        }
        e.kind = NativeFileType::Directory;
        e.mode = 0o040700;
        e.permissions = "rwx------".into();
        let r = NativeStatReceipt {
            path: "a".into(),
            entry: Some(e),
        };
        let mut c = MetadataCache::default();
        c.retain(
            "make_dir",
            "a",
            "make_dir_result",
            &serde_json::to_value(r).unwrap(),
        )
        .unwrap();
        assert!(c.complete);
        let mut c = MetadataCache::default();
        c.retain(
            "file_stat",
            "missing",
            "file_stat_result",
            &serde_json::json!({"path":"missing","entry":null}),
        )
        .unwrap();
        assert!(c.complete);
    }
}
