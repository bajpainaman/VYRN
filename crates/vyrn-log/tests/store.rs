//! Hash-chain tamper tests and block-store tests, including crash truncation of the file store.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use vyrn_log::block::{self, ChainError, check_anchor, check_link, header_hash, order_root};
use vyrn_log::store::{
    Block, BlockKind, BlockStore, FileStore, MemStore, StoreError, decode_record, encode_record,
};
use vyrn_types::{BlockHeader, BookId, Epoch, Hash, Height, PktHash, SessionId, StepId};

const SEED: [u8; 32] = [9; 32];

/// `n` chained, signed blocks starting at height 10.
fn chain(n: u64) -> Vec<Block> {
    let mut out: Vec<Block> = Vec::new();
    let mut prev = Hash([0xAA; 32]);
    let mut next_step = 1;
    for i in 0..n {
        let order_a: Vec<u8> = (0..(i as usize * 37 % 500)).map(|x| x as u8).collect();
        let order_b = vec![i as u8; (i as usize * 11) % 90];
        let last_step = next_step + i % 3; // some blocks hold several steps
        let header = BlockHeader {
            height: Height(10 + i),
            epoch: Epoch(5),
            book: BookId(2),
            first_step: StepId(next_step),
            last_step: StepId(last_step),
            prev,
            order_root: order_root(&order_a, &order_b),
            data_root: Hash([i as u8; 32]),
            seq_sig: [0; 64],
        };
        let header = block::sign_header(&header, &SEED);
        prev = header_hash(&header);
        next_step = last_step + 1;
        out.push(Block {
            header,
            tenure: 0,
            kind: BlockKind::Normal,
            order_a,
            order_b,
            pkt_hashes: (0..i).map(PktHash).collect(),
            data: vec![0x5A; (i as usize * 1000) % 7000],
            unavailable: if i % 4 == 1 {
                vec![(SessionId(7), 3)]
            } else {
                vec![]
            },
        });
    }
    out
}

#[test]
fn chain_links_and_signatures_hold() {
    let c = chain(6);
    let key = vyrn_crypto::ed25519::public_key(&SEED);
    assert_eq!(
        check_anchor(Hash([0xAA; 32]), Height(9), &c[0].header),
        Ok(())
    );
    for w in c.windows(2) {
        assert_eq!(check_link(&w[0].header, &w[1].header), Ok(()));
    }
    assert!(c.iter().all(|b| block::verify_seq_sig(&b.header, &key)));
}

#[test]
fn tampering_with_any_header_field_breaks_the_chain() {
    let c = chain(3);
    let (p, n) = (c[0].header, c[1].header);
    let key = vyrn_crypto::ed25519::public_key(&SEED);
    // Each field of the previous header is covered by header_hash, so changing it breaks `prev`.
    let edits: [fn(&mut BlockHeader); 8] = [
        |h| h.height.0 += 1,
        |h| h.epoch.0 ^= 1,
        |h| h.book.0 ^= 1,
        |h| h.first_step.0 ^= 1,
        |h| h.last_step.0 += 1,
        |h| h.prev.0[31] ^= 1,
        |h| h.order_root.0[0] ^= 1,
        |h| h.data_root.0[17] ^= 0x80,
    ];
    for e in edits {
        let mut t = p;
        e(&mut t);
        assert!(
            check_link(&t, &n).is_err(),
            "edited prev header still links"
        );
        assert!(
            !block::verify_seq_sig(&t, &key),
            "edited header still verifies"
        );
    }
    // seq_sig is outside header_hash: changing it keeps the link but fails verification.
    let mut t = p;
    t.seq_sig[0] ^= 1;
    assert_eq!(check_link(&t, &n), Ok(()));
    assert!(!block::verify_seq_sig(&t, &key));

    let mut t = n;
    t.prev.0[0] ^= 1;
    assert_eq!(check_link(&p, &t), Err(ChainError::Prev));
    let mut t = n;
    t.height.0 += 1;
    assert_eq!(check_link(&p, &t), Err(ChainError::Height));
    let mut t = n;
    t.first_step.0 += 1;
    assert_eq!(check_link(&p, &t), Err(ChainError::Steps));
    let mut t = n;
    t.last_step.0 = t.first_step.0 - 2;
    assert_eq!(check_link(&p, &t), Err(ChainError::Steps));
    let mut t = n;
    t.book.0 += 1;
    assert_eq!(check_link(&p, &t), Err(ChainError::Book));
    let mut t = n;
    t.epoch.0 += 2;
    assert_eq!(check_link(&p, &t), Err(ChainError::Epoch));
}

#[test]
fn epoch_boundary_restarts_steps() {
    let c = chain(1);
    let p = c[0].header;
    let mut n = BlockHeader {
        height: Height(p.height.0 + 1),
        epoch: Epoch(p.epoch.0 + 1),
        first_step: StepId(1),
        last_step: StepId(0), // an empty first block
        prev: header_hash(&p),
        ..p
    };
    assert_eq!(check_link(&p, &n), Ok(()));
    n.first_step = StepId(p.last_step.0 + 1);
    n.last_step = n.first_step;
    assert_eq!(check_link(&p, &n), Err(ChainError::Steps));
}

#[test]
fn record_round_trips_and_rejects_any_flipped_bit() {
    for b in chain(5) {
        let rec = encode_record(&b).unwrap();
        assert_eq!(rec.len() % 4096, 0);
        assert_eq!(decode_record(&rec).unwrap(), b);
        for i in (0..rec.len()).step_by(97) {
            let mut t = rec.clone();
            t[i] ^= 0x01;
            assert!(decode_record(&t).is_err(), "flip at {i} accepted");
        }
    }
}

fn exercise<S: BlockStore>(s: &mut S) {
    let c = chain(8);
    assert_eq!(s.range(), None);
    for b in &c {
        s.put(b).unwrap();
    }
    assert_eq!(s.range(), Some((Height(10), Height(17))));
    assert_eq!(s.get(Height(13)).unwrap().unwrap(), c[3]);
    assert_eq!(s.get(Height(9)).unwrap(), None);
    assert_eq!(s.get(Height(18)).unwrap(), None);
    // The header-only read agrees with the full record at every height, across drives.
    for b in &c {
        assert_eq!(s.header(b.header.height).unwrap(), Some(b.header));
    }
    assert_eq!(s.header(Height(9)).unwrap(), None);
    assert_eq!(s.header(Height(18)).unwrap(), None);
    let read: Vec<Block> = s.read(Height(10), Height(17)).map(Result::unwrap).collect();
    assert_eq!(read, c);
    // A gap or a block that does not link is refused.
    let extra = chain(10);
    assert!(matches!(
        s.put(&extra[9]),
        Err(StoreError::NotNext { got: 19, want: 18 })
    ));
    let mut bad = extra[8].clone();
    bad.header.prev.0[0] ^= 1;
    assert!(matches!(
        s.put(&bad),
        Err(StoreError::Chain(ChainError::Prev))
    ));
    s.put(&extra[8]).unwrap();
    assert_eq!(
        vyrn_log::store::log_hash(s).unwrap(),
        Some(header_hash(&extra[8].header))
    );
    // Reading past the end reports the missing height.
    let tail: Vec<_> = s.read(Height(17), Height(19)).collect();
    assert_eq!(tail.len(), 3);
    assert!(matches!(tail[2], Err(StoreError::Missing(19))));
}

#[test]
fn mem_store() {
    exercise(&mut MemStore::default());
}

struct TempDirs(Vec<PathBuf>);

impl TempDirs {
    fn new(name: &str, n: usize) -> Self {
        let root = std::env::temp_dir().join(format!("vyrn-log-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        Self((0..n).map(|i| root.join(format!("drive{i}"))).collect())
    }
}

impl Drop for TempDirs {
    fn drop(&mut self) {
        if let Some(root) = self.0.first().and_then(|p| p.parent()) {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

#[test]
fn file_store_persists_across_reopen() {
    let dirs = TempDirs::new("reopen", 3);
    exercise(&mut FileStore::open(&dirs.0).unwrap());
    let s = FileStore::open(&dirs.0).unwrap();
    assert_eq!(s.range(), Some((Height(10), Height(18))));
    let read: Vec<Block> = s.read(Height(10), Height(18)).map(Result::unwrap).collect();
    assert_eq!(read[..8], chain(8)[..]);
}

#[test]
fn file_store_recovers_from_a_torn_write() {
    let c = chain(7);
    let dirs = TempDirs::new("torn", 2);
    {
        let mut s = FileStore::open(&dirs.0).unwrap();
        for b in &c[..6] {
            s.put(b).unwrap();
        }
    }
    // Simulate a crash while writing height 16 (drive 0): only a prefix of its record lands.
    let rec = encode_record(&c[6]).unwrap();
    let path = FileStore::drive_path(&dirs.0[0]);
    let good_len = std::fs::metadata(&path).unwrap().len();
    for cut in [1usize, 255, 256, 300, rec.len() - 1] {
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&rec[..cut]).unwrap();
        }
        let s = FileStore::open(&dirs.0).unwrap();
        assert_eq!(s.range(), Some((Height(10), Height(15))), "cut {cut}");
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            good_len,
            "torn tail truncated"
        );
        assert_eq!(
            s.read(Height(10), Height(15)).filter(|r| r.is_ok()).count(),
            6
        );
    }
    // After recovery, the next block is written normally.
    let mut s = FileStore::open(&dirs.0).unwrap();
    s.put(&c[6]).unwrap();
    drop(s);
    let s = FileStore::open(&dirs.0).unwrap();
    assert_eq!(s.get(Height(16)).unwrap().unwrap(), c[6]);
}

#[test]
fn file_store_drops_everything_after_a_corrupt_record() {
    let c = chain(6);
    let dirs = TempDirs::new("corrupt", 2);
    {
        let mut s = FileStore::open(&dirs.0).unwrap();
        for b in &c {
            s.put(b).unwrap();
        }
    }
    // Flip one byte inside height 12's record (drive 0, second record). Heights 12..=15 go:
    // 13 and 15 are intact on drive 1, but they no longer chain to a kept block.
    let path = FileStore::drive_path(&dirs.0[0]);
    let mut bytes = std::fs::read(&path).unwrap();
    let first = encode_record(&c[0]).unwrap().len();
    bytes[first + 300] ^= 0x40;
    std::fs::write(&path, &bytes).unwrap();
    let s = FileStore::open(&dirs.0).unwrap();
    assert_eq!(s.range(), Some((Height(10), Height(11))));
    assert_eq!(
        std::fs::metadata(FileStore::drive_path(&dirs.0[1]))
            .unwrap()
            .len(),
        encode_record(&c[1]).unwrap().len() as u64
    );
}

#[test]
fn file_store_serves_concurrent_reads() {
    let c = chain(8);
    let dirs = TempDirs::new("concurrent", 1);
    let mut s = FileStore::open(&dirs.0).unwrap();
    for b in &c {
        s.put(b).unwrap();
    }
    std::thread::scope(|sc| {
        for t in 0..4u64 {
            let (s, c) = (&s, &c);
            sc.spawn(move || {
                for i in 0..200u64 {
                    let k = ((i * 7 + t * 3) % 8) as usize;
                    assert_eq!(s.get(Height(10 + k as u64)).unwrap().unwrap(), c[k]);
                }
            });
        }
    });
}

#[test]
fn file_store_refuses_a_reordered_drive_list_without_touching_files() {
    let c = chain(4);
    let dirs = TempDirs::new("reorder", 2);
    {
        let mut s = FileStore::open(&dirs.0).unwrap();
        for b in &c {
            s.put(b).unwrap();
        }
    }
    let lens: Vec<u64> = dirs
        .0
        .iter()
        .map(|d| std::fs::metadata(FileStore::drive_path(d)).unwrap().len())
        .collect();
    let swapped = vec![dirs.0[1].clone(), dirs.0[0].clone()];
    assert!(matches!(
        FileStore::open(&swapped),
        Err(StoreError::Drive | StoreError::Placement)
    ));
    let after: Vec<u64> = dirs
        .0
        .iter()
        .map(|d| std::fs::metadata(FileStore::drive_path(d)).unwrap().len())
        .collect();
    assert_eq!(lens, after, "no file was truncated");
    assert_eq!(
        FileStore::open(&dirs.0).unwrap().range(),
        Some((Height(10), Height(13)))
    );
}

#[test]
fn file_store_has_one_owner() {
    let dirs = TempDirs::new("lock", 2);
    let first = FileStore::open(&dirs.0).unwrap();
    assert!(matches!(FileStore::open(&dirs.0), Err(StoreError::Locked)));
    drop(first);
    FileStore::open(&dirs.0).unwrap();
}

#[test]
fn file_store_refuses_a_missing_drive_without_touching_files() {
    let c = chain(6);
    let dirs = TempDirs::new("missing", 2);
    {
        let mut s = FileStore::open(&dirs.0).unwrap();
        for b in &c {
            s.put(b).unwrap();
        }
    }
    let healthy = FileStore::drive_path(&dirs.0[0]);
    let len = std::fs::metadata(&healthy).unwrap().len();
    // Drive 1 is replaced by an empty directory (an unmounted or swapped disk).
    std::fs::remove_dir_all(&dirs.0[1]).unwrap();
    assert!(matches!(FileStore::open(&dirs.0), Err(StoreError::Drive)));
    assert_eq!(
        std::fs::metadata(&healthy).unwrap().len(),
        len,
        "no block was truncated"
    );
}
