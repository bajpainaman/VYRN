//! The drop-copy session's transport: `Noise_NK_25519_ChaChaPoly_SHA512` (10 §8.5 item 5).
//!
//! 10 §8.3 asks for TCP with Noise or TLS 1.3. No TLS 1.3 stack is on the 11 §2.2 allowlist
//! (`ring` and `aws-lc-rs` are banned, 01 PQ-12), so the drop copy speaks Noise (\[Guessing\]):
//!
//! - **NK.** The client knows the server's static X25519 key from its onboarding; the client has
//!   no Noise static key, because the account's Ed25519 login inside the stream (§8.5 item 2)
//!   authenticates it. The two handshake messages are `-> e, es` and `<- e, ee`, 48 bytes each
//!   (the ephemeral key and the tag of an empty payload).
//! - **Prologue.** `"vyrn v1 dropcopy noise"` then the book (u16 LE), so a handshake for one
//!   book's server never completes against another's.
//! - **Framing.** Every message, handshake and transport, is a u16 big-endian length and then
//!   that many bytes, at most 65 535 (the Noise limit). Each transport message carries the next
//!   bytes of the §8.5 session, so the session wire is unchanged inside it.
//! - **Nonces.** 0 upward per direction; a direction that reaches `u64::MAX` fails rather than
//!   reuse a nonce.
//!
//! The handshake and transport are pure functions of their inputs ([`initiate`],
//! [`respond`], [`Transport`]); the ephemeral keys come from the caller, so
//! `tests/dc_noise_vectors.txt` (written by an independent script) checks them byte for byte.
//! [`NoiseStream`] puts them on any `Read + Write`.

use std::io::{Read, Write};

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};
use sha2::{Digest, Sha512};
use vyrn_crypto::x25519;
use vyrn_types::BookId;

pub const PROTOCOL: &[u8] = b"Noise_NK_25519_ChaChaPoly_SHA512";
pub const PROLOGUE: &[u8] = b"vyrn v1 dropcopy noise";
/// Bytes of each handshake message.
pub const HANDSHAKE_BYTES: usize = 48;
/// The largest Noise message.
pub const MAX_MSG: usize = 65_535;
pub const TAG_BYTES: usize = 16;
/// The largest plaintext of one transport message.
pub const MAX_PLAIN: usize = MAX_MSG - TAG_BYTES;

const HASH: usize = 64;
const BLOCK: usize = 128;

/// Why a handshake or a message failed. Every failure ends the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoiseError {
    /// A tag did not verify (a forged, corrupted or replayed message, or the wrong server key).
    Auth,
    /// A low-order public key: the Diffie-Hellman output would be all zero.
    Key,
    /// A message of the wrong length.
    Len,
    /// A direction used up its nonces.
    Nonce,
}

impl std::fmt::Display for NoiseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "noise: {self:?}")
    }
}

impl std::error::Error for NoiseError {}

impl From<NoiseError> for std::io::Error {
    fn from(e: NoiseError) -> Self {
        Self::new(std::io::ErrorKind::InvalidData, e)
    }
}

fn hmac(key: &[u8; HASH], parts: &[&[u8]]) -> [u8; HASH] {
    let mut k = [0u8; BLOCK];
    k[..HASH].copy_from_slice(key);
    let mut inner = Sha512::new();
    inner.update(k.map(|b| b ^ 0x36));
    for p in parts {
        inner.update(p);
    }
    let mut outer = Sha512::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// Noise's HKDF with two outputs.
fn hkdf2(ck: &[u8; HASH], ikm: &[u8]) -> ([u8; HASH], [u8; HASH]) {
    let t = hmac(ck, &[ikm]);
    let a = hmac(&t, &[&[1]]);
    let b = hmac(&t, &[&a, &[2]]);
    (a, b)
}

fn key32(x: &[u8; HASH]) -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&x[..32]);
    k
}

/// One direction's `CipherState`.
#[derive(Clone)]
struct Cipher {
    aead: ChaCha20Poly1305,
    n: u64,
}

impl Cipher {
    fn new(k: [u8; 32]) -> Self {
        Self {
            aead: ChaCha20Poly1305::new(&k.into()),
            n: 0,
        }
    }

    fn nonce(&mut self) -> Result<Nonce, NoiseError> {
        if self.n == u64::MAX {
            return Err(NoiseError::Nonce);
        }
        let mut b = [0u8; 12];
        b[4..].copy_from_slice(&self.n.to_le_bytes());
        self.n += 1;
        Ok(b.into())
    }

    /// Appends the ciphertext and tag of `pt` to `out`.
    fn seal(&mut self, ad: &[u8], pt: &[u8], out: &mut Vec<u8>) -> Result<(), NoiseError> {
        let nonce = self.nonce()?;
        let at = out.len();
        out.extend_from_slice(pt);
        let tag = self
            .aead
            .encrypt_inout_detached(&nonce, ad, out[at..].as_mut().into())
            .map_err(|_| NoiseError::Len)?;
        out.extend_from_slice(&tag);
        Ok(())
    }

    /// Decrypts `ct` (ciphertext then tag) in place; returns the plaintext's length.
    fn open(&mut self, ad: &[u8], ct: &mut [u8]) -> Result<usize, NoiseError> {
        let n = ct.len().checked_sub(TAG_BYTES).ok_or(NoiseError::Len)?;
        let (body, tag) = ct.split_at_mut(n);
        let tag = Tag::try_from(&*tag).map_err(|_| NoiseError::Len)?;
        let nonce = self.nonce()?;
        self.aead
            .decrypt_inout_detached(&nonce, ad, body.into(), &tag)
            .map_err(|_| NoiseError::Auth)?;
        Ok(n)
    }
}

/// The handshake's `SymmetricState`.
struct Sym {
    ck: [u8; HASH],
    h: [u8; HASH],
    k: Option<Cipher>,
}

impl Sym {
    fn new(book: BookId, rs: &[u8; 32]) -> Self {
        let mut h = [0u8; HASH];
        h[..PROTOCOL.len()].copy_from_slice(PROTOCOL);
        let mut s = Self { ck: h, h, k: None };
        let mut prologue = PROLOGUE.to_vec();
        prologue.extend_from_slice(&book.0.to_le_bytes());
        s.mix_hash(&prologue);
        // Pre-message `<- s`.
        s.mix_hash(rs);
        s
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut d = Sha512::new();
        d.update(self.h);
        d.update(data);
        self.h = d.finalize().into();
    }

    fn mix_key(&mut self, ikm: &[u8; 32]) {
        let (ck, k) = hkdf2(&self.ck, ikm);
        self.ck = ck;
        self.k = Some(Cipher::new(key32(&k)));
    }

    /// `EncryptAndHash` of the empty payload: its tag.
    fn tag(&mut self, out: &mut Vec<u8>) -> Result<(), NoiseError> {
        let at = out.len();
        let h = self.h;
        self.k.as_mut().ok_or(NoiseError::Key)?.seal(&h, &[], out)?;
        let c = out[at..].to_vec();
        self.mix_hash(&c);
        Ok(())
    }

    fn check_tag(&mut self, tag: &[u8]) -> Result<(), NoiseError> {
        let h = self.h;
        let mut t = tag.to_vec();
        self.k.as_mut().ok_or(NoiseError::Key)?.open(&h, &mut t)?;
        self.mix_hash(tag);
        Ok(())
    }

    /// `Split`: (initiator → responder, responder → initiator).
    fn split(&self) -> (Cipher, Cipher) {
        let (a, b) = hkdf2(&self.ck, &[]);
        (Cipher::new(key32(&a)), Cipher::new(key32(&b)))
    }
}

fn dh(secret: &[u8; 32], public: &[u8; 32]) -> Result<[u8; 32], NoiseError> {
    x25519::shared_secret(secret, public).ok_or(NoiseError::Key)
}

/// A finished handshake: one cipher per direction.
#[derive(Clone)]
pub struct Transport {
    tx: Cipher,
    rx: Cipher,
    /// The handshake hash, the same on both ends.
    hash: [u8; HASH],
}

impl Transport {
    /// Appends one framed message carrying `pt` (≤ [`MAX_PLAIN`] bytes) to `out`.
    pub fn seal(&mut self, pt: &[u8], out: &mut Vec<u8>) -> Result<(), NoiseError> {
        if pt.len() > MAX_PLAIN {
            return Err(NoiseError::Len);
        }
        let len = u16::try_from(pt.len() + TAG_BYTES).map_err(|_| NoiseError::Len)?;
        out.extend_from_slice(&len.to_be_bytes());
        self.tx.seal(&[], pt, out)
    }

    /// Decrypts one message body (after its length prefix) in place; returns the plaintext's
    /// length.
    pub fn open(&mut self, msg: &mut [u8]) -> Result<usize, NoiseError> {
        self.rx.open(&[], msg)
    }

    pub fn handshake_hash(&self) -> [u8; HASH] {
        self.hash
    }
}

/// The client's side after `-> e, es`, waiting for `<- e, ee`.
pub struct Initiator {
    sym: Sym,
    e: [u8; 32],
}

/// Starts a handshake to the server whose static public key is `server`, with ephemeral
/// secret `e`. Returns the state and message 1.
pub fn initiate(
    book: BookId,
    server: &[u8; 32],
    e: &[u8; 32],
) -> Result<(Initiator, [u8; HANDSHAKE_BYTES]), NoiseError> {
    let mut sym = Sym::new(book, server);
    let ep = x25519::public_key(e);
    let mut out = ep.to_vec();
    sym.mix_hash(&ep);
    sym.mix_key(&dh(e, server)?);
    sym.tag(&mut out)?;
    let msg = out.try_into().map_err(|_| NoiseError::Len)?;
    Ok((Initiator { sym, e: *e }, msg))
}

impl Initiator {
    /// Takes message 2.
    pub fn finish(mut self, msg: &[u8; HANDSHAKE_BYTES]) -> Result<Transport, NoiseError> {
        let (re, tag) = msg.split_at(32);
        let re: [u8; 32] = re.try_into().map_err(|_| NoiseError::Len)?;
        self.sym.mix_hash(&re);
        self.sym.mix_key(&dh(&self.e, &re)?);
        self.sym.check_tag(tag)?;
        let (tx, rx) = self.sym.split();
        Ok(Transport {
            tx,
            rx,
            hash: self.sym.h,
        })
    }
}

/// The server's side: takes message 1 with static secret `s` and ephemeral secret `e`, and
/// returns the transport and message 2.
pub fn respond(
    book: BookId,
    s: &[u8; 32],
    e: &[u8; 32],
    msg: &[u8; HANDSHAKE_BYTES],
) -> Result<(Transport, [u8; HANDSHAKE_BYTES]), NoiseError> {
    let mut sym = Sym::new(book, &x25519::public_key(s));
    let (re, tag) = msg.split_at(32);
    let re: [u8; 32] = re.try_into().map_err(|_| NoiseError::Len)?;
    sym.mix_hash(&re);
    sym.mix_key(&dh(s, &re)?);
    sym.check_tag(tag)?;
    let ep = x25519::public_key(e);
    let mut out = ep.to_vec();
    sym.mix_hash(&ep);
    sym.mix_key(&dh(e, &re)?);
    sym.tag(&mut out)?;
    let (i2r, r2i) = sym.split();
    let msg = out.try_into().map_err(|_| NoiseError::Len)?;
    Ok((
        Transport {
            tx: r2i,
            rx: i2r,
            hash: sym.h,
        },
        msg,
    ))
}

/// Sets the read timeout of the underlying stream (`None`: blocking).
pub type SetTimeout<T> = fn(&mut T, Option<std::time::Duration>) -> std::io::Result<()>;

/// An absolute read deadline and how to cap each underlying read by it.
pub type Deadline<T> = (std::time::Instant, SetTimeout<T>);

/// Before every underlying read: past the deadline is `TimedOut`, else the read may block at
/// most until it. So a client that trickles bytes, or sends empty messages, gets no more time
/// than the deadline in all.
fn before_read<T>(io: &mut T, d: Option<Deadline<T>>) -> std::io::Result<()> {
    if let Some((at, set)) = d {
        let left = at.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        set(io, Some(left))?;
    }
    Ok(())
}

/// A read that failed once the deadline passed reports `TimedOut` (a capped socket read
/// reports `WouldBlock` on Linux).
fn timed<T>(e: std::io::Error, d: Option<Deadline<T>>) -> std::io::Error {
    match d {
        Some((at, _)) if std::time::Instant::now() >= at => std::io::ErrorKind::TimedOut.into(),
        _ => e,
    }
}

fn read_full<T: Read>(io: &mut T, buf: &mut [u8], d: Option<Deadline<T>>) -> std::io::Result<()> {
    let mut got = 0;
    while got < buf.len() {
        before_read(io, d)?;
        match io.read(&mut buf[got..]) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(timed(e, d)),
        }
    }
    Ok(())
}

fn read_frame<T: Read>(
    io: &mut T,
    buf: &mut Vec<u8>,
    d: Option<Deadline<T>>,
) -> std::io::Result<()> {
    let mut len = [0u8; 2];
    read_full(io, &mut len, d)?;
    buf.resize(usize::from(u16::from_be_bytes(len)), 0);
    read_full(io, buf, d)
}

/// A Noise transport over `T`: `Read` yields the peer's plaintext, each `write` sends one
/// message. A partial message read before a timeout is kept, so a read after a
/// `WouldBlock` / `TimedOut` resumes it. With a [`Deadline`], no read (empty messages
/// included) waits past it.
pub struct NoiseStream<T> {
    io: T,
    deadline: Option<Deadline<T>>,
    t: Transport,
    /// Received bytes of the message being read (length prefix included).
    raw: Vec<u8>,
    /// Decrypted plaintext not yet read, from `pos` on.
    plain: Vec<u8>,
    pos: usize,
    out: Vec<u8>,
}

impl<T: Read + Write> NoiseStream<T> {
    /// The server's end: reads message 1, sends message 2. `deadline` bounds the handshake and
    /// every read after it (the login deadline, 10 §8.5 item 5) until [`NoiseStream::set_deadline`]
    /// changes it.
    pub fn accept(
        mut io: T,
        book: BookId,
        s: &[u8; 32],
        e: &[u8; 32],
        deadline: Option<Deadline<T>>,
    ) -> std::io::Result<Self> {
        let mut m1 = Vec::new();
        read_frame(&mut io, &mut m1, deadline)?;
        let m1: [u8; HANDSHAKE_BYTES] = m1.try_into().map_err(|_| NoiseError::Len)?;
        let (t, m2) = respond(book, s, e, &m1)?;
        let mut f = (HANDSHAKE_BYTES as u16).to_be_bytes().to_vec();
        f.extend_from_slice(&m2);
        io.write_all(&f)?;
        let mut st = Self::new(io, t);
        st.deadline = deadline;
        Ok(st)
    }

    /// The client's end: sends message 1, reads message 2.
    pub fn connect(
        mut io: T,
        book: BookId,
        server: &[u8; 32],
        e: &[u8; 32],
    ) -> std::io::Result<Self> {
        let (st, m1) = initiate(book, server, e)?;
        let mut f = (HANDSHAKE_BYTES as u16).to_be_bytes().to_vec();
        f.extend_from_slice(&m1);
        io.write_all(&f)?;
        let mut m2 = Vec::new();
        read_frame(&mut io, &mut m2, None)?;
        let m2: [u8; HANDSHAKE_BYTES] = m2.try_into().map_err(|_| NoiseError::Len)?;
        Ok(Self::new(io, st.finish(&m2)?))
    }

    fn new(io: T, t: Transport) -> Self {
        Self {
            io,
            deadline: None,
            t,
            raw: Vec::new(),
            plain: Vec::new(),
            pos: 0,
            out: Vec::new(),
        }
    }

    /// Sets or clears the read deadline.
    pub fn set_deadline(&mut self, deadline: Option<Deadline<T>>) {
        self.deadline = deadline;
    }

    /// The underlying stream, for its timeouts.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.io
    }

    pub fn handshake_hash(&self) -> [u8; HASH] {
        self.t.handshake_hash()
    }

    /// Reads until `raw` holds `want` bytes; `Ok(false)` at end of stream before any byte.
    fn fill(&mut self, want: usize) -> std::io::Result<bool> {
        let mut b = [0u8; 4096];
        while self.raw.len() < want {
            let k = (want - self.raw.len()).min(b.len());
            before_read(&mut self.io, self.deadline)?;
            let d = self.deadline;
            match self.io.read(&mut b[..k]).map_err(|e| timed(e, d))? {
                0 if self.raw.is_empty() => return Ok(false),
                0 => return Err(std::io::ErrorKind::UnexpectedEof.into()),
                n => self.raw.extend_from_slice(&b[..n]),
            }
        }
        Ok(true)
    }
}

impl<T: Read + Write> Read for NoiseStream<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.pos == self.plain.len() {
            if !self.fill(2)? {
                return Ok(0);
            }
            let len = usize::from(u16::from_be_bytes([self.raw[0], self.raw[1]]));
            self.fill(2 + len)?;
            let mut body = self.raw.split_off(2);
            self.raw.clear();
            let n = self.t.open(&mut body)?;
            body.truncate(n);
            self.plain = body;
            self.pos = 0;
        }
        let n = buf.len().min(self.plain.len() - self.pos);
        buf[..n].copy_from_slice(&self.plain[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl<T: Read + Write> Write for NoiseStream<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = buf.len().min(MAX_PLAIN);
        self.out.clear();
        self.t.seal(&buf[..n], &mut self.out)?;
        self.io.write_all(&self.out)?;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush()
    }
}
