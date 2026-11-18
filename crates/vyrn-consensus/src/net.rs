//! A voter's Simplex network: `commonware-p2p` `authenticated::lookup` over TCP, authenticated
//! and encrypted (spec/07-replication.md §3.1), with peers named by key.
//!
//! | Contract | Type | Spec |
//! |---|---|---|
//! | Who a voter connects to | [`Peer`]: `vote_key`, `node_key`, `repl_addr` of each voter | 07 §3.1, §13.1 |
//! | What `Engine::start` takes | [`VoterNet`]: three channels and a blocker, keyed by vote key | 07 §6.3 |
//! | Where `Silence` and its TailReport go | [`VoterNet::tail`], a fourth channel | 07 §3.1, §9.1 |
//! | The standby's TailReport (07 §9.5) | a non-voting peer keyed by `seq_order[1]`'s `seq_key`, heard on the tail channel only ([`start_standby`]) | 07 §3.1, §9.5 |
//!
//! **Two keys.** A connection authenticates the peer's `node_key` (its p2p identity, as in the
//! roster). Simplex names participants by `vote_key`. [`VoterNet`]'s senders, receivers and
//! blocker translate one to the other through the committee's [`Peer`] list, so a message from a
//! connection is always attributed to the voter whose `node_key` it authenticated. A DEV peer
//! may use one key for both.
//!
//! **Tuning** (not in 07; DEV values, labelled): `Config::recommended` with private addresses
//! allowed (the replication VLANs are private), 16 handshakes per second per IP (several voters
//! may share a host), a 200 ms dial period and a 1 s reconnect cooldown, so a restarted voter
//! rejoins within a second. Each channel's quota is [`RATE`].

use crate::cert::NAMESPACE;
use commonware_actor::{Feedback, Unreliable};
use commonware_consensus::simplex::{max_payload_size, scheme::ed25519::Scheme};
use commonware_cryptography::{ChaCha20Poly1305, blake3::Digest, ed25519};
use commonware_p2p::authenticated::lookup;
use commonware_p2p::{
    Address, AddressableManager as _, BlockedSubscription, Blocker, CheckedSender, LimitedSender,
    Message, Receiver, Recipients,
};
use commonware_runtime::{IoBufs, Quota, tokio::Context};
use commonware_stream::{
    SakeCups,
    cups::{self, Cups},
    sake::{self, Sake},
};
use commonware_utils::ordered::Map;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use vyrn_types::PubKey;

/// Simplex's channels on the lookup network.
const CH_VOTE: u64 = 0;
const CH_CERT: u64 = 1;
const CH_RESOLVER: u64 = 2;
/// `Silence` and its TailReport (07 §3.1: "TailReports use commonware-p2p"). *Reading*
/// (transport): a channel of its own on the voters' network, next to Simplex's three. The
/// standby joins the network as a non-voting peer and is heard on this channel only: its
/// messages on vote, cert or resolver are dropped, and Simplex's broadcasts never reach it.
const CH_TAIL: u64 = 3;
/// Messages per second one peer may send on one channel: three votes a view at ~1 kHz views,
/// with headroom for catch-up. Commonware sizes each channel's mailbox as peers × this burst, so
/// it also bounds memory (100 000 cost ~0.5 GB per voter).
pub const RATE: u32 = 10_000;

/// One voter as the network sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub vote_key: PubKey,
    pub node_key: PubKey,
    pub repl_addr: SocketAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum NetErr {
    #[error("a key is not a valid Ed25519 public key")]
    Key,
    #[error("two peers share a vote_key or a node_key")]
    Duplicate,
}

fn key(k: &PubKey) -> Result<ed25519::PublicKey, NetErr> {
    use commonware_codec::DecodeExt;
    ed25519::PublicKey::decode(k.to_vec()).map_err(|_| NetErr::Key)
}

/// `node_key` ↔ `vote_key` of the committee, and the standby's key when it is a peer.
#[derive(Debug)]
struct Keys {
    node_of: BTreeMap<ed25519::PublicKey, ed25519::PublicKey>,
    vote_of: BTreeMap<ed25519::PublicKey, ed25519::PublicKey>,
    standby: Option<ed25519::PublicKey>,
}

impl Keys {
    fn to_node(&self, r: Recipients<ed25519::PublicKey>) -> Recipients<ed25519::PublicKey> {
        let map = |k: ed25519::PublicKey| self.node_of.get(&k).cloned();
        match r {
            // With a standby among the peers, "all" means the committee's nodes.
            Recipients::All if self.standby.is_some() => {
                Recipients::Some(self.node_of.values().cloned().collect())
            }
            Recipients::All => Recipients::All,
            Recipients::Some(ks) => Recipients::Some(ks.into_iter().filter_map(map).collect()),
            Recipients::One(k) if self.standby.as_ref() == Some(&k) => Recipients::One(k),
            Recipients::One(k) => {
                map(k).map_or_else(|| Recipients::Some(Vec::new()), Recipients::One)
            }
        }
    }
}

/// A Simplex channel's sender, addressed by vote key.
#[derive(Clone, Debug)]
pub struct VoteSender<S> {
    inner: S,
    keys: Arc<Keys>,
}

/// The recipients a [`VoteSender`] checked.
pub struct VoteChecked<C> {
    inner: C,
    keys: Arc<Keys>,
}

impl<S> LimitedSender for VoteSender<S>
where
    S: LimitedSender<PublicKey = ed25519::PublicKey>,
{
    type PublicKey = ed25519::PublicKey;
    type Checked<'a>
        = VoteChecked<S::Checked<'a>>
    where
        Self: 'a;

    fn check(
        &mut self,
        recipients: Recipients<ed25519::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        let keys = Arc::clone(&self.keys);
        let inner = self.inner.check(keys.to_node(recipients))?;
        Ok(VoteChecked { inner, keys })
    }
}

impl<C: CheckedSender<PublicKey = ed25519::PublicKey>> CheckedSender for VoteChecked<C> {
    type PublicKey = ed25519::PublicKey;

    fn recipients(&self) -> Vec<ed25519::PublicKey> {
        self.inner
            .recipients()
            .iter()
            .filter_map(|k| self.keys.vote_of.get(k).cloned())
            .collect()
    }

    fn send(self, message: impl Into<IoBufs> + Send, priority: bool) -> Unreliable<Feedback> {
        self.inner.send(message, priority)
    }
}

/// A Simplex channel's receiver: each message attributed to the vote key of its connection.
#[derive(Debug)]
pub struct VoteReceiver<R> {
    inner: R,
    keys: Arc<Keys>,
}

impl<R: Receiver<PublicKey = ed25519::PublicKey>> Receiver for VoteReceiver<R> {
    type Error = R::Error;
    type PublicKey = ed25519::PublicKey;

    async fn recv(&mut self) -> Result<Message<ed25519::PublicKey>, R::Error> {
        loop {
            let (from, msg) = self.inner.recv().await?;
            // Only committee nodes connect (the lookup network admits tracked peers only).
            if let Some(v) = self.keys.vote_of.get(&from) {
                return Ok((v.clone(), msg));
            }
        }
    }

    fn capacity(&self) -> NonZeroUsize {
        self.inner.capacity()
    }
}

/// Blocks the node of a vote key.
#[derive(Clone, Debug)]
pub struct VoteBlocker<B> {
    inner: B,
    keys: Arc<Keys>,
}

impl<B: Blocker<PublicKey = ed25519::PublicKey>> Blocker for VoteBlocker<B> {
    type PublicKey = ed25519::PublicKey;

    fn block(&mut self, peer: ed25519::PublicKey) -> Feedback {
        match self.keys.node_of.get(&peer) {
            Some(n) => self.inner.block(n.clone()),
            None => Feedback::Ok,
        }
    }

    /// Node keys, as the network reports them. Simplex reads this only to stop counting a peer;
    /// it gets vote keys, and a node key that is no vote key matches no participant.
    fn blocked(&mut self) -> BlockedSubscription<ed25519::PublicKey> {
        self.inner.blocked()
    }
}

type Channel = (
    VoteSender<lookup::Sender<ed25519::PublicKey, Context>>,
    VoteReceiver<lookup::Receiver<ed25519::PublicKey>>,
);

/// The tail channel: encoded `Silence` messages among the voters and from the standby (07
/// §3.1, §9.1, §9.5).
pub struct TailChannel {
    send: VoteSender<lookup::Sender<ed25519::PublicKey, Context>>,
    recv: lookup::Receiver<ed25519::PublicKey>,
    keys: Arc<Keys>,
}

impl TailChannel {
    /// Sends `bytes` to every voter (the standby's to every voter too). Reliable while a
    /// connection is up; a peer that was disconnected misses it, so the caller repeats its own.
    pub fn broadcast(&mut self, bytes: Vec<u8>) {
        use commonware_p2p::Sender as _;
        let _ = self.send.send(Recipients::All, bytes, true);
    }

    /// Sends `bytes` to the standby only, if it is a peer (07 §9.5: the seal header it opens
    /// its tenure on). *Reading* (wire): the 190-byte `BlockHeader`, which the standby accepts
    /// only when its hash is a verified kind-1 certificate's `last_hash`.
    pub fn send_standby(&mut self, bytes: Vec<u8>) {
        use commonware_p2p::Sender as _;
        if let Some(k) = self.keys.standby.clone() {
            let _ = self.send.send(Recipients::One(k), bytes, true);
        }
    }

    /// The next message and who sent it: the vote key of the voter whose connection carried
    /// it, or the standby's `seq_key`. `None` once the network stopped.
    pub async fn recv(&mut self) -> Option<(PubKey, Vec<u8>)> {
        loop {
            let (from, msg) = self.recv.recv().await.ok()?;
            let who = match self.keys.vote_of.get(&from) {
                Some(v) => v.clone(),
                None if self.keys.standby.as_ref() == Some(&from) => from,
                None => continue,
            };
            let key: &[u8] = who.as_ref();
            return Some((PubKey::try_from(key).ok()?, msg.as_ref().to_vec()));
        }
    }
}

/// What `simplex::Engine::start` takes, and the blocker for `voter::config`.
pub struct VoterNet {
    pub vote: Channel,
    pub cert: Channel,
    pub resolver: Channel,
    /// `Silence` messages, encoded ([`crate::tail::Silence::encode`]).
    pub tail: TailChannel,
    pub blocker: VoteBlocker<lookup::Oracle<ed25519::PublicKey>>,
}

/// The standby as a peer of the voters' network (07 §9.5): its `seq_key`, which it
/// authenticates with, and its `repl_addr`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Standby {
    pub seq_key: PubKey,
    pub addr: SocketAddr,
}

/// Starts this voter's lookup network on `listen`, authenticated as `node_seed`'s key, with the
/// committee `peers` (this voter among them), and the `standby` if any, as peer set 0.
pub fn start(
    context: Context,
    node_seed: [u8; 32],
    listen: SocketAddr,
    peers: &[Peer],
    standby: Option<Standby>,
) -> Result<VoterNet, NetErr> {
    let (mut network, oracle, keys) = network(context, node_seed, listen, peers, standby)?;
    let quota = Quota::per_second(NonZeroU32::new(RATE).unwrap_or(NonZeroU32::MIN));
    let mut channel = |c| {
        let (s, r) = network.register(c, quota);
        let keys = Arc::clone(&keys);
        (
            VoteSender {
                inner: s,
                keys: Arc::clone(&keys),
            },
            VoteReceiver { inner: r, keys },
        )
    };
    let (vote, cert, resolver) = (channel(CH_VOTE), channel(CH_CERT), channel(CH_RESOLVER));
    let tail = tail_channel(&mut network, &keys);
    network.start();
    Ok(VoterNet {
        vote,
        cert,
        resolver,
        tail,
        blocker: VoteBlocker {
            inner: oracle,
            keys,
        },
    })
}

/// The standby's side (07 §9.5): it joins the committee `peers`' network on `listen`,
/// authenticated as `seq_seed`'s key, and registers only the tail channel, where it hears the
/// voters' `Silence` and sends its own TailReport.
pub fn start_standby(
    context: Context,
    seq_seed: [u8; 32],
    listen: SocketAddr,
    peers: &[Peer],
) -> Result<TailChannel, NetErr> {
    let (mut network, _oracle, keys) = network(context, seq_seed, listen, peers, None)?;
    let tail = tail_channel(&mut network, &keys);
    network.start();
    Ok(tail)
}

fn tail_channel(
    network: &mut lookup::Network<Context, SakeCups<ed25519::PrivateKey, ChaCha20Poly1305>>,
    keys: &Arc<Keys>,
) -> TailChannel {
    let quota = Quota::per_second(NonZeroU32::new(RATE).unwrap_or(NonZeroU32::MIN));
    let (s, r) = network.register(CH_TAIL, quota);
    TailChannel {
        send: VoteSender {
            inner: s,
            keys: Arc::clone(keys),
        },
        recv: r,
        keys: Arc::clone(keys),
    }
}

type Net = (
    lookup::Network<Context, SakeCups<ed25519::PrivateKey, ChaCha20Poly1305>>,
    lookup::Oracle<ed25519::PublicKey>,
    Arc<Keys>,
);

fn network(
    context: Context,
    seed: [u8; 32],
    listen: SocketAddr,
    peers: &[Peer],
    standby: Option<Standby>,
) -> Result<Net, NetErr> {
    use commonware_codec::DecodeExt;
    let signer = ed25519::PrivateKey::decode(seed.to_vec()).map_err(|_| NetErr::Key)?;
    let mut node_of = BTreeMap::new();
    let mut vote_of = BTreeMap::new();
    let mut addrs = Vec::new();
    for p in peers {
        let (v, n) = (key(&p.vote_key)?, key(&p.node_key)?);
        if node_of.insert(v.clone(), n.clone()).is_some() || vote_of.insert(n.clone(), v).is_some()
        {
            return Err(NetErr::Duplicate);
        }
        addrs.push((n, Address::Symmetric(p.repl_addr)));
    }
    let standby = match standby {
        Some(s) => {
            let k = key(&s.seq_key)?;
            if vote_of.contains_key(&k) {
                return Err(NetErr::Duplicate);
            }
            addrs.push((k.clone(), Address::Symmetric(s.addr)));
            Some(k)
        }
        None => None,
    };
    let keys = Arc::new(Keys {
        node_of,
        vote_of,
        standby,
    });
    // The peer set counts this node too: a voter is among `peers`, the standby is not.
    let local = commonware_cryptography::Signer::public_key(&signer);
    let n = addrs.len() + usize::from(!addrs.iter().any(|(k, _)| *k == local));
    let n = NonZeroUsize::new(n).unwrap_or(NonZeroUsize::MIN);
    let max = u32::try_from(peers.len()).unwrap_or(u32::MAX);
    let handshake: SakeCups<_, ChaCha20Poly1305> = Cups::new(
        Sake {
            signer,
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(10),
            version: sake::Version::V1,
        },
        cups::Version::V1,
    );
    let mut cfg = lookup::Config::recommended(
        handshake,
        NAMESPACE,
        listen,
        n,
        commonware_p2p::max_message_size(&[
            max_payload_size::<Scheme, Digest>(max),
            crate::tail::SILENCE_MAX_BYTES,
        ]),
        NonZeroUsize::new(1024).unwrap_or(NonZeroUsize::MIN),
    );
    cfg.allow_private_ips = true;
    // Only registered peer IPs may handshake at all; 16/s lets several voters share one host.
    cfg.allowed_handshake_rate_per_ip =
        Quota::per_second(NonZeroU32::new(16).unwrap_or(NonZeroU32::MIN));
    cfg.dial_frequency = Duration::from_millis(200);
    cfg.peer_connection_cooldown = Duration::from_secs(1);
    let (network, mut oracle) = lookup::Network::new(context, cfg);
    let _ = oracle.track(0, Map::from_iter_dedup(addrs));
    Ok((network, oracle, keys))
}
