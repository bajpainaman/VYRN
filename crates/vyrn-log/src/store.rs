//! Block storage and the log reader for replay (07 §8.2).
//!
//! # REP_BlockRecord (one per block, padded with zeros to a multiple of 4096 bytes)
//!
//! ```text
//! off size field
//!   0   8  magic        "PBBLK001"
//!   8   8  height       = header.height
//!  16   4  epoch        = header.epoch
//!  20   1  tenure
//!  21   1  kind         0 normal, 1 seal
//!  22   2  reserved     0
//!  24 190  BlockHeader  (crate::block)
//! 214   4  order_len    bytes of order bytes, substream A then B
//! 218   4  hash_len     bytes of the pkt_hash list (8 × PacketRecords other than Advance)
//! 222   4  data_len     bytes of payload data, O-order
//! 226   4  n_unavail    entries of the unavailable list
//! 230   4  order_a_len  bytes of substream A's order bytes (≤ order_len)        [vyrn-log]
//! 234  16  check        first 16 bytes of BLAKE3 of the record with these 16 zeroed [vyrn-log]
//! 250   6  reserved     0
//! 256   …  order bytes │ pkt_hash list (u64 each) │ data │ unavailable (session u32,
//!          pkt_seq u32 each) │ zero padding
//! ```
//!
//! 07 §8.2 gives offsets 0–229 and leaves 230–255 reserved. `order_a_len` and `check` are this
//! crate's use of the reserved bytes: the first splits the order bytes so `order_root` can be
//! recomputed, the second detects torn writes. A reader rejects a record with nonzero
//! reserved or padding bytes.
//!
//! [`FileStore`] appends records to one file per drive (block `h` on drive `h mod drives`),
//! syncs each write, and on open keeps the longest run of consecutive heights whose records
//! check and whose `prev` links chain; it truncates everything after that run, which is how a
//! crash mid-write is undone. io_uring and O_DIRECT are not used yet.

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use vyrn_crypto::hash::hash;
use vyrn_types::{BlockHeader, Height, PktHash, SessionId};

use crate::block::{
    ChainError, HEADER_BYTES, check_link, decode_header, encode_header, header_hash, order_root,
};
use crate::leb::Reader;

pub const RECORD_MAGIC: &[u8; 8] = b"PBBLK001";
pub const RECORD_HEAD_BYTES: usize = 256;
pub const RECORD_ALIGN: usize = 4096;
const CHECK_OFF: usize = 234;
const CHECK_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockKind {
    Normal = 0,
    Seal = 1,
}

/// One stored block: header `h`, the order bytes of `h`, and the payloads `h` references
/// (07 §2.1). This is what a replica writes once `verify` passes and what replay reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub tenure: u8,
    pub kind: BlockKind,
    pub order_a: Vec<u8>,
    /// Empty with one substream.
    pub order_b: Vec<u8>,
    /// A's PacketRecords then B's, O-order, Advance records excluded.
    pub pkt_hashes: Vec<PktHash>,
    /// Payload bytes in O-order; the store does not interpret them.
    pub data: Vec<u8>,
    pub unavailable: Vec<(SessionId, u32)>,
}

impl Block {
    pub fn order_root(&self) -> vyrn_types::Hash {
        order_root(&self.order_a, &self.order_b)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("record is malformed or fails its check")]
    Corrupt,
    #[error("a region does not fit its u32 length field")]
    TooLarge,
    #[error("height {got} is not the next height {want}")]
    NotNext { got: u64, want: u64 },
    #[error("chain: {0}")]
    Chain(#[from] ChainError),
    #[error("a record sits on the wrong drive: the drive list differs from the one written")]
    Placement,
    #[error("another FileStore holds this drive")]
    Locked,
    #[error("height {0} is not stored")]
    Missing(u64),
    #[error("order_root does not match the stored order bytes")]
    OrderRoot,
}

fn len32(n: usize) -> Result<[u8; 4], StoreError> {
    Ok(u32::try_from(n)
        .map_err(|_| StoreError::TooLarge)?
        .to_le_bytes())
}

/// The record bytes of `b`.
pub fn encode_record(b: &Block) -> Result<Vec<u8>, StoreError> {
    let mut out = Vec::with_capacity(RECORD_ALIGN);
    out.extend_from_slice(RECORD_MAGIC);
    out.extend_from_slice(&b.header.height.0.to_le_bytes());
    out.extend_from_slice(&b.header.epoch.0.to_le_bytes());
    out.extend_from_slice(&[b.tenure, b.kind as u8, 0, 0]);
    out.extend_from_slice(&encode_header(&b.header));
    let order_len = b
        .order_a
        .len()
        .checked_add(b.order_b.len())
        .ok_or(StoreError::TooLarge)?;
    let hash_len = b
        .pkt_hashes
        .len()
        .checked_mul(8)
        .ok_or(StoreError::TooLarge)?;
    out.extend_from_slice(&len32(order_len)?);
    out.extend_from_slice(&len32(hash_len)?);
    out.extend_from_slice(&len32(b.data.len())?);
    out.extend_from_slice(&len32(b.unavailable.len())?);
    out.extend_from_slice(&len32(b.order_a.len())?);
    out.resize(RECORD_HEAD_BYTES, 0);
    out.extend_from_slice(&b.order_a);
    out.extend_from_slice(&b.order_b);
    b.pkt_hashes
        .iter()
        .for_each(|h| out.extend_from_slice(&h.0.to_le_bytes()));
    out.extend_from_slice(&b.data);
    for (s, p) in &b.unavailable {
        out.extend_from_slice(&s.0.to_le_bytes());
        out.extend_from_slice(&p.to_le_bytes());
    }
    let padded = out
        .len()
        .div_ceil(RECORD_ALIGN)
        .saturating_mul(RECORD_ALIGN);
    out.resize(padded, 0);
    let check = hash(&out);
    if let Some(dst) = out.get_mut(CHECK_OFF..CHECK_OFF.saturating_add(CHECK_LEN)) {
        dst.iter_mut().zip(&check.0).for_each(|(d, s)| *d = *s);
    }
    Ok(out)
}

/// The total record length the 256-byte head announces.
pub fn record_len(head: &[u8]) -> Result<usize, StoreError> {
    let mut r = Reader::new(head.get(214..230).ok_or(StoreError::Corrupt)?);
    let mut total = RECORD_HEAD_BYTES;
    let order = r.u32().map_err(|_| StoreError::Corrupt)?;
    let hashes = r.u32().map_err(|_| StoreError::Corrupt)?;
    let data = r.u32().map_err(|_| StoreError::Corrupt)?;
    let n_unavail = r.u32().map_err(|_| StoreError::Corrupt)?;
    let unavail = u64::from(n_unavail).saturating_mul(8);
    for n in [
        u64::from(order),
        u64::from(hashes),
        u64::from(data),
        unavail,
    ] {
        let n = usize::try_from(n).map_err(|_| StoreError::Corrupt)?;
        total = total.checked_add(n).ok_or(StoreError::Corrupt)?;
    }
    Ok(total.div_ceil(RECORD_ALIGN).saturating_mul(RECORD_ALIGN))
}

/// Parses and checks one record.
pub fn decode_record(rec: &[u8]) -> Result<Block, StoreError> {
    let c = StoreError::Corrupt;
    if rec.len() != record_len(rec)? {
        return Err(c);
    }
    let mut zeroed = rec.to_vec();
    let stored = zeroed
        .get_mut(CHECK_OFF..CHECK_OFF.saturating_add(CHECK_LEN))
        .ok_or(StoreError::Corrupt)?;
    let want: Vec<u8> = stored.to_vec();
    stored.fill(0);
    if hash(&zeroed).0.get(..CHECK_LEN) != Some(&want[..]) {
        return Err(StoreError::Corrupt);
    }
    let mut r = Reader::new(rec);
    let e = |_| StoreError::Corrupt;
    let magic: [u8; 8] = r.array().map_err(e)?;
    let height = r.u64().map_err(e)?;
    let epoch = r.u32().map_err(e)?;
    let tenure = r.u8().map_err(e)?;
    let kind = match r.u8().map_err(e)? {
        0 => BlockKind::Normal,
        1 => BlockKind::Seal,
        _ => return Err(StoreError::Corrupt),
    };
    let reserved = r.u16().map_err(e)?;
    let hb: [u8; HEADER_BYTES] = r.array().map_err(e)?;
    let header = decode_header(&hb);
    let order_len = usize::try_from(r.u32().map_err(e)?).map_err(|_| StoreError::Corrupt)?;
    let hash_len = usize::try_from(r.u32().map_err(e)?).map_err(|_| StoreError::Corrupt)?;
    let data_len = usize::try_from(r.u32().map_err(e)?).map_err(|_| StoreError::Corrupt)?;
    let n_unavail = r.u32().map_err(e)?;
    let order_a_len = usize::try_from(r.u32().map_err(e)?).map_err(|_| StoreError::Corrupt)?;
    r.bytes(CHECK_LEN).map_err(e)?;
    let tail_reserved = r.bytes(6).map_err(e)?;
    if &magic != RECORD_MAGIC
        || height != header.height.0
        || epoch != header.epoch.0
        || reserved != 0
        || tail_reserved.iter().any(|&b| b != 0)
        || order_a_len > order_len
        || hash_len % 8 != 0
    {
        return Err(StoreError::Corrupt);
    }
    let order_a = r.bytes(order_a_len).map_err(e)?.to_vec();
    let order_b = r
        .bytes(order_len.wrapping_sub(order_a_len))
        .map_err(e)?
        .to_vec();
    let mut pkt_hashes = Vec::new();
    for _ in 0..hash_len / 8 {
        pkt_hashes.push(PktHash(r.u64().map_err(e)?));
    }
    let data = r.bytes(data_len).map_err(e)?.to_vec();
    let mut unavailable = Vec::new();
    for _ in 0..n_unavail {
        unavailable.push((SessionId(r.u32().map_err(e)?), r.u32().map_err(e)?));
    }
    if r.rest().iter().any(|&b| b != 0) {
        return Err(StoreError::Corrupt);
    }
    Ok(Block {
        header,
        tenure,
        kind,
        order_a,
        order_b,
        pkt_hashes,
        data,
        unavailable,
    })
}

/// Where blocks live. Heights are written once, in order, with no gaps, and each header links
/// to the one before it ([`check_link`]).
pub trait BlockStore {
    /// Writes block `b`, durably before it returns. `b.header.height` must be
    /// [`next_height`](Self::next_height) unless the store is empty.
    fn put(&mut self, b: &Block) -> Result<(), StoreError>;
    fn get(&self, height: Height) -> Result<Option<Block>, StoreError>;
    /// The lowest and highest stored heights.
    fn range(&self) -> Option<(Height, Height)>;

    fn next_height(&self) -> Option<Height> {
        self.range().map(|(_, hi)| Height(hi.0.saturating_add(1)))
    }

    /// Reads heights `from..=to` in order, checking each link and order root.
    fn read(&self, from: Height, to: Height) -> LogReader<'_, Self>
    where
        Self: Sized,
    {
        LogReader {
            store: self,
            next: from.0,
            end: to.0,
            prev: None,
        }
    }
}

/// The write rule both stores apply: the next height, linked to the newest stored header.
fn check_next(last: Option<&BlockHeader>, b: &Block) -> Result<(), StoreError> {
    if let Some(p) = last {
        let want = p.height.0.saturating_add(1);
        if b.header.height.0 != want {
            return Err(StoreError::NotNext {
                got: b.header.height.0,
                want,
            });
        }
        check_link(p, &b.header)?;
    }
    Ok(())
}

/// An in-memory store for tests and `vyrn-sim`.
#[derive(Clone, Debug, Default)]
pub struct MemStore {
    blocks: std::collections::BTreeMap<u64, Block>,
}

impl BlockStore for MemStore {
    fn put(&mut self, b: &Block) -> Result<(), StoreError> {
        check_next(self.blocks.values().next_back().map(|b| &b.header), b)?;
        self.blocks.insert(b.header.height.0, b.clone());
        Ok(())
    }

    fn get(&self, height: Height) -> Result<Option<Block>, StoreError> {
        Ok(self.blocks.get(&height.0).cloned())
    }

    fn range(&self) -> Option<(Height, Height)> {
        let lo = self.blocks.keys().next()?;
        let hi = self.blocks.keys().next_back()?;
        Some((Height(*lo), Height(*hi)))
    }
}

#[derive(Debug)]
struct Drive {
    file: File,
    len: u64,
}

/// A file per drive; block `h` goes to drive `h mod drives`.
#[derive(Debug)]
pub struct FileStore {
    drives: Vec<Drive>,
    /// `index[i]` locates height `first + i`: (drive, offset, length).
    index: Vec<(usize, u64, u64)>,
    first: u64,
    last_header: Option<BlockHeader>,
}

/// The file a drive directory holds.
pub const DRIVE_FILE: &str = "blocks.pbl";

impl FileStore {
    /// Opens or creates the store over `dirs` (one per drive), recovering from a crash.
    pub fn open(dirs: &[PathBuf]) -> Result<Self, StoreError> {
        if dirs.is_empty() {
            return Err(StoreError::Corrupt);
        }
        let mut drives = Vec::new();
        // Only headers and locations: recovery memory scales with the index, not the log.
        let mut found: Vec<(BlockHeader, usize, u64, u64)> = Vec::new();
        for (d, dir) in dirs.iter().enumerate() {
            let missing: Vec<PathBuf> = dir
                .ancestors()
                .take_while(|a| !a.as_os_str().is_empty() && !a.exists())
                .map(Path::to_path_buf)
                .collect();
            std::fs::create_dir_all(dir)?;
            // A new directory's entry lives in its parent, so sync each parent too.
            for m in &missing {
                if let Some(parent) = m.parent().filter(|p| !p.as_os_str().is_empty()) {
                    sync_dir(parent)?;
                }
            }
            let path = dir.join(DRIVE_FILE);
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)?;
            // One writer per drive for the store's lifetime; the lock drops with the File.
            file.try_lock().map_err(|e| match e {
                std::fs::TryLockError::WouldBlock => StoreError::Locked,
                std::fs::TryLockError::Error(e) => StoreError::Io(e),
            })?;
            sync_dir(dir)?;
            let len = file.metadata()?.len();
            for (h, off, n) in scan(&file, len)? {
                found.push((h, d, off, n));
            }
            drives.push(Drive { file, len });
        }
        // A valid record on the wrong drive means the drive list changed; refuse before
        // recovery truncates anything.
        let n_drives = drives.len() as u64;
        if found
            .iter()
            .any(|(h, d, ..)| drive_of(h.height, n_drives) != *d)
        {
            return Err(StoreError::Placement);
        }
        found.sort_by_key(|(h, ..)| h.height.0);
        // Keep the longest prefix of consecutive, chained heights, drive-placed by height.
        let mut keep = 0usize;
        for i in 0..found.len() {
            let ok = match (i.checked_sub(1).and_then(|p| found.get(p)), found.get(i)) {
                (_, None) => false,
                (None, Some(_)) => true,
                (Some((p, ..)), Some((h, ..))) => check_link(p, h).is_ok(),
            };
            if !ok {
                break;
            }
            keep = i.saturating_add(1);
        }
        // Truncate each drive after its last kept record.
        let mut ends = vec![0u64; drives.len()];
        for (_, d, off, n) in found.iter().take(keep) {
            if let Some(e) = ends.get_mut(*d) {
                *e = (*e).max(off.saturating_add(*n));
            }
        }
        for (drive, end) in drives.iter_mut().zip(&ends) {
            if drive.len != *end {
                drive.file.set_len(*end)?;
                drive.file.sync_all()?;
                drive.len = *end;
            }
        }
        let kept: Vec<_> = found.into_iter().take(keep).collect();
        Ok(Self {
            first: kept.first().map_or(0, |(h, ..)| h.height.0),
            last_header: kept.last().map(|(h, ..)| *h),
            index: kept.into_iter().map(|(_, d, off, n)| (d, off, n)).collect(),
            drives,
        })
    }

    /// The drive directories' files, for tests and tools.
    pub fn drive_path(dir: &Path) -> PathBuf {
        dir.join(DRIVE_FILE)
    }
}

fn drive_of(h: Height, n: u64) -> usize {
    usize::try_from(h.0.checked_rem(n).unwrap_or(0)).unwrap_or(0)
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<(), StoreError> {
    File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> Result<(), StoreError> {
    Ok(())
}

/// Reads exactly `buf.len()` bytes at `off` without moving the file cursor, so concurrent
/// [`BlockStore::get`] calls on one drive never race.
#[cfg(unix)]
fn read_at(file: &File, buf: &mut [u8], off: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(file, buf, off)
}

#[cfg(windows)]
fn read_at(file: &File, mut buf: &mut [u8], mut off: u64) -> std::io::Result<()> {
    while !buf.is_empty() {
        let n = std::os::windows::fs::FileExt::seek_read(file, buf, off)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf = buf.get_mut(n..).unwrap_or_default();
        off = off.saturating_add(n as u64);
    }
    Ok(())
}

/// The header and location of every record that checks, from the start of the file up to the
/// first that does not. Each record is decoded and dropped; payloads are not retained.
fn scan(file: &File, len: u64) -> Result<Vec<(BlockHeader, u64, u64)>, StoreError> {
    let mut out = Vec::new();
    let mut off = 0u64;
    let mut head = [0u8; RECORD_HEAD_BYTES];
    loop {
        if off.saturating_add(RECORD_HEAD_BYTES as u64) > len {
            break;
        }
        read_at(file, &mut head, off)?;
        let Ok(n) = record_len(&head) else { break };
        let n64 = n as u64;
        if off.saturating_add(n64) > len {
            break;
        }
        let mut rec = vec![0u8; n];
        read_at(file, &mut rec, off)?;
        let Ok(b) = decode_record(&rec) else { break };
        out.push((b.header, off, n64));
        off = off.saturating_add(n64);
    }
    Ok(out)
}

impl BlockStore for FileStore {
    fn put(&mut self, b: &Block) -> Result<(), StoreError> {
        check_next(self.last_header.as_ref(), b)?;
        let rec = encode_record(b)?;
        let n = self.drives.len() as u64;
        let d = drive_of(b.header.height, n);
        let drive = self.drives.get_mut(d).ok_or(StoreError::Corrupt)?;
        let off = drive.len;
        drive.file.seek(SeekFrom::Start(off))?;
        drive.file.write_all(&rec)?;
        drive.file.sync_data()?;
        drive.len = off.saturating_add(rec.len() as u64);
        if self.index.is_empty() {
            self.first = b.header.height.0;
        }
        self.index.push((d, off, rec.len() as u64));
        self.last_header = Some(b.header);
        Ok(())
    }

    fn get(&self, height: Height) -> Result<Option<Block>, StoreError> {
        let Some(i) = height.0.checked_sub(self.first) else {
            return Ok(None);
        };
        let Some(&(d, off, n)) = usize::try_from(i).ok().and_then(|i| self.index.get(i)) else {
            return Ok(None);
        };
        let drive = self.drives.get(d).ok_or(StoreError::Corrupt)?;
        let mut rec = vec![0u8; usize::try_from(n).map_err(|_| StoreError::Corrupt)?];
        read_at(&drive.file, &mut rec, off)?;
        let b = decode_record(&rec)?;
        if b.header.height != height {
            return Err(StoreError::Corrupt);
        }
        Ok(Some(b))
    }

    fn range(&self) -> Option<(Height, Height)> {
        let n = self.index.len() as u64;
        let last = self.first.checked_add(n)?.checked_sub(1)?;
        (n > 0).then_some((Height(self.first), Height(last)))
    }
}

/// Reads stored blocks in height order for replay and catch-up. Each block's order bytes are
/// checked against its `order_root`, and each header against the previous one
/// ([`check_link`]). `seq_sig` and certificates are the caller's to check.
#[derive(Debug)]
pub struct LogReader<'a, S: BlockStore> {
    store: &'a S,
    next: u64,
    end: u64,
    prev: Option<BlockHeader>,
}

impl<S: BlockStore> Iterator for LogReader<'_, S> {
    type Item = Result<Block, StoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next > self.end {
            return None;
        }
        let h = Height(self.next);
        self.next = self.next.saturating_add(1);
        let out = (|| {
            let b = self.store.get(h)?.ok_or(StoreError::Missing(h.0))?;
            if b.order_root() != b.header.order_root {
                return Err(StoreError::OrderRoot);
            }
            if let Some(p) = &self.prev {
                check_link(p, &b.header)?;
            }
            self.prev = Some(b.header);
            Ok(b)
        })();
        if out.is_err() {
            self.next = self.end.saturating_add(1);
        }
        Some(out)
    }
}

/// `header_hash` of the newest block, the `log_hash` of a `HandoffRecord` (07 §2.2).
pub fn log_hash<S: BlockStore>(store: &S) -> Result<Option<vyrn_types::Hash>, StoreError> {
    let Some((_, hi)) = store.range() else {
        return Ok(None);
    };
    Ok(store.get(hi)?.map(|b| header_hash(&b.header)))
}
