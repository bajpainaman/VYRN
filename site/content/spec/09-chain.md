# 09. Chain mode: validators, custody, authentication, commitments, slashing

Draft 0.2, 2026-11-13. Normative for `CHAIN` mode. `01-conventions.md` wins over this chapter, and
its §14 is binding. Source: `DESIGN.md` §7.

## 1. Scope and the chain on one page

In `CHAIN` mode the exchange is a blockchain. The order stream, the consensus and the replay engine
are the ones that `05-engine.md` and `07-replication.md` specify. This chapter adds what a chain
needs on top of them: a validator set with keys and bonds, custody of user funds, authentication
that a public network can trust, slashing, state commitments, light clients and economics.

The decisions, each stated once:

1. **Five operators, fifteen nodes.** Each operator runs one node in each home. The committee of an
   epoch is the 5 nodes in that epoch's home. `N_CHAIN = 5`, `Q_CHAIN = 4`, `F = 1`.
2. **One sequencer operator per epoch.** The role rotates by `e mod 5`. Because 3 and 5 are
   coprime, every operator sequences every home once in 15 epochs (5 days).
3. **The sequencing operator holds `K_seq` and never `K_com`.** The other 4 operators hold `K_com`
   through a per-epoch committee key. A forged packet needs both keys, which needs 2 byzantine
   operators, and 2 > `F`.
4. **The sequencing operator is never the Simplex leader.** Leaders rotate over the other 4. So the
   leader can always compute the exclusion list, and the sequencer cannot censor the forced path.
5. **Everything that is not an order enters on a low-rate transaction path.** The Simplex leader
   includes it. It takes effect no later than a fixed boundary `FIN_GATE_BLOCKS` + 1 (9) book
   blocks after the last book block in the same chain block. The sequencer never runs more than 8
   closed blocks ahead of finality. If finality lags more, the book halts rather than issue a fill
   that cannot be final within 10 ms (01 §14.9).
6. **A packet with a bad `tag_com` is busted, not erased.** Matching replays as executed. The fills
   of the bad packet's orders are reversed at the boundary, and the session's bond pays the
   counterparties. The engine never rewinds. A bust is a correction of a misbehaving client, not
   a finality exemption: the verdict is final with the block, ≤ 10 ms after the packet was sent.
7. **Custody is an Ethereum L1 bridge contract** that checks 4-of-5 secp256k1 signatures, credits
   deposits only after L1 finality, and releases withdrawals after a 1 h challenge period. If the
   validators stop posting for 14 days, the contract opens an escape hatch against the last posted
   balance root.
8. **Commitments:** a BLAKE3 log chain per chain block, a sparse Merkle tree of balances every
   1 s, and a lattice hash of resting orders every 1 s over the net diff.
9. **Slashing is automatic** for evidence that signatures prove: sequencer equivocation, double
   votes, fence violations, double commit votes, bridge equivocation. Absence (a withheld handoff)
   is proved by a quorum attestation and slashed less.
10. **Front-running by the sequencer cannot be prevented at 1 µs.** It is capped by rotation, a
    bond, and published per-sequencer statistics that are computed from certified data.

```
                         one epoch e, home H = home(e), sequencer operator s = seq_op(e)
  wallet ──SessionOpen (tx path, signed)──► any validator ──► Simplex leader ──► chain block
                                                                                    │
  client ── packet (tag_seq, tag_com) ──► vyrn-seq (operator s)  ── fills ≤ 1 µs ──► client
     │                                        │ order stream + seq_sig per book block
     └── same packet ──► vyrn-data (op ≠ s) ──► │
                                              ▼
            ┌──────────── committee of home H: 5 validator boxes ──────────────┐
            │ op s : replay, vote (blind on exclusions), never leader          │
            │ op a,b,c,d : replay, check tag_com with K_com, compute exclusion │
            │              lists, lead views in turn, vote                     │
            └──────────────┬───────────────────────────────────────────────────┘
                           │ certificate (4 of 5)          every 1 s: StateCommit + 4 sigs
                           ▼                                        │
         finalized chain log ──► followers in the 2 other homes      ▼
                           │                          L1 bridge post (secp256k1 4-of-5)
                           └──► public archive ──► anyone replays    every 60 s / 1 h
```

### 1.1 Hard constraints

- **C-UNIX:** every VYRN process in this chapter is a Rust binary on Linux (`vyrn-seq`,
  `vyrn-validator`, `vyrn-data`). The L1 client is third-party software (an Ethereum execution client
  and a consensus client) on Linux. Light-client code runs on any Unix.
- **C-NOCHIP:** all cryptography runs on general-purpose CPUs: SipHash-2-4, BLAKE3 (SIMD),
  Ed25519, X25519, secp256k1. A COTS HSM or hardware wallet may store cold keys. It runs no
  VYRN logic and sits on no packet path.
- **C-COTS:** validator boxes are `REF` boxes (01 §10). The commit box (§9.6) is any COTS server.
- **C-ONEBIN:** `vyrn-validator` is one binary. The roles `val` and `commit` are configuration.

### 1.2 The hard requirements in CHAIN mode (01 §14.0)

| Requirement | How CHAIN meets it |
|---|---|
| 1 µs, as a maximum | The chain adds one SipHash (`tag_seq`, inside 14.2's 45 ns per packet) and a gate flag read to the lane. Item ops are capped per lane per block (§4.6). A gate halt answers every packet with `Reject BOOK_HALTED` within the 1 µs. Nothing waits on a validator. |
| 1B msgs/s on one book | Sized at `WL-REF`: 145.5M packets/s (02 §5.2). `tag_com` costs ~3 cores per validator box, hashing ~5 (§5.1, §9.2). |
| 10 ms finality for every accepted order | §4.8: ≤ 8.11 ms from block start with one fault, and the gate halts the book before it issues a fill that the model cannot finalize. |
| The 8 h move | The committee is the 5 nodes of the epoch's home (§2.1). Keys, schedule and committee keys are fixed 4 epochs ahead (§2.3, §2.4, §3.1). |
| 5 validators | `N_CHAIN = 5`, `Q_CHAIN = 4`, 3 Rust and 2 Vx (§2.1). The sequencer box never votes (01 §14.4). |

## 2. Validator set

### 2.1 Operators, nodes and boxes

| Term | Meaning |
|---|---|
| operator | One independent organization. Identified by `OpIdx` (u8, 0–4). It is the unit of trust, of bonds and of slashing. |
| node | The set of boxes one operator runs in one home. Identified by `(OpIdx, HomeCode)`. 15 nodes in total. |
| validator box | The box in a node that runs `vyrn-validator --role=val`: replay, `tag_com` checks, votes. One per node. |
| commit box | The box in a node that runs `vyrn-validator --role=commit`: SMT, LtHash, L1 client, archive, RPC. One per node. |
| sequencer box | A box that runs `vyrn-seq` for one book or book group. Each operator keeps one in F1 and one in F2 of every home (03). In epoch e, the F1 box of `seq_op(e)` is live and the F2 box of `next_seq(e, seq_op(e))` is the warm standby (§3.2). A sequencer box never votes and never holds a `G` private half. |
| data node | A box that runs `vyrn-data`. Every node runs at least two. |
| committee(e) | The 5 nodes `(i, home(e))` for i = 0–4. They vote in epoch e. |
| `home(e)` | `[TYO, LDN, NYC][e mod 3]` unless a certified `HomeOverride` for e exists (`08-epochs.md`). Genesis epoch 0 is TYO. |

Each operator is assigned a client kind at genesis: operators 0, 1, 2 run the Rust validator
client, and operators 3 and 4 run the Vx client (`CLIENT_SPLIT_CHAIN`). A node's validator box
always runs its operator's client kind. **`INV-CHN-SPLIT`: an operator's consensus vote and commit
vote are always cast by its validator box, never by its sequencer box.** This is 01 §14.4 in CHAIN
form: the sequencing operator votes from its validator box. The reason: the sequencer box runs Rust
for every operator. If the sequencer box voted, an epoch sequenced by a Vx operator would give Rust
4 votes, and Rust alone could finalize.

### 2.2 Key hierarchy

Every key has one purpose. A key never signs a message of another purpose, and every signed message
starts with a domain-separation context (§17.3).

```
  operator identity key OIK_i  (Ed25519, cold, offline)
     │ signs: NodeCert, governance votes, bond actions, its own key rotation
     ├──► NodeCert(i, TYO) ─┬─ node key      NK  (Ed25519)  p2p identity, TagFault, attestations
     ├──► NodeCert(i, LDN)  ├─ vote key      VK  (Ed25519)  consensus votes, commit votes
     └──► NodeCert(i, NYC)  ├─ seq key       SK  (Ed25519)  seq_sig on book blocks
                            └─ exchange key  XK  (X25519; + ML-KEM-768 from E_pq)   K_seq derivation, committee-key transport
  bridge key BK_i   (secp256k1, HSM)    signs L1 posts and signer rotations
  guardian key GK_i (secp256k1, online) pauses the bridge, vetoes an L1 post
```

| Key | Scheme | Where it lives | Rotation |
|---|---|---|---|
| `OIK_i` | Ed25519; hybrid Ed25519 + ML-DSA-65 (scheme 2) before `E_pq` (01 §14.20) | Air-gapped Linux machine or COTS HSM | Governance (§2.10), timelocked |
| `NK`, `VK`, `SK`, `XK` | Ed25519 / X25519; `NK`, `VK`, `SK` hybrid Ed25519 + ML-DSA-44 (scheme 1) from `E_pq`; `XK` a hybrid X25519 + ML-KEM-768 `KexKey` from `E_pq` (01 §14.20 G) | The node's boxes, in memory, loaded from an encrypted file at start | New `NodeCert`; active from the node's next active epoch |
| `BK_i` | secp256k1 | COTS HSM on the commit box | L1 signer rotation (§6.7) |
| `GK_i` | secp256k1 | Online watcher process on the commit box | L1 signer rotation |

Why per-node keys and not one key per operator: a key leaked in one home does not let the thief sign
in the other two. Why the votes still count per operator: certificates list `(OpIdx, sig)` (01 §4),
and the verifier picks the key `VK(i, home(e))`. A light client needs only the key table of each
epoch (§10).

### 2.3 NodeCert

```
NodeCert {
    chain_id:     u32,
    op:           OpIdx,
    home:         HomeCode,
    serial:       u32,          // +1 per rotation of this node's keys
    valid_from:   Epoch,        // first epoch in which these keys may sign
    scheme:       SigScheme,    // 0 or 1 (01 §3): the scheme of node_key, vote_key, seq_key
    node_key:     PubKey,       // 32 B (scheme 0) or 1,344 B (scheme 1)
    vote_key:     PubKey,
    seq_key:      PubKey,
    xchg_key:     KexKey,       // 32 B (scheme 0) or 1,216 B (scheme 1): X25519 ‖ ML-KEM-768 (01 §3)
    client_kind:  u8,           // 0 Rust, 1 Vx
    sig:          Sig,          // by OIK_op, in OIK's scheme, over ctx "vyrn      v1 nodecert" ‖ fields
}
```

A scheme-1 `NodeCert` is invalid unless the ML-KEM-768 part of every `KexKey` in it passes the
FIPS 203 encapsulation-key check (01 §14.20 KG2).

**Scheme of the cert in force.** For epoch e, the cert in force is the newest one with
`valid_from ≤ e` **and** `scheme = EpoConfig(e).sig_scheme`. A hybrid `NodeCert` for the switch
has `valid_from = E_pq` and is included in a chain block of an epoch ≤ `E_pq −
CHN_KEY_LEAD_EPOCHS` (the lead rule below, 01 §14.20 SG4). So the hybrid keys never sign in an
epoch that still requires scheme 0, and the scheme-0 cert stays in force up to `E_pq − 1`. A
scheme-0 `NodeCert` is not in force for any epoch ≥ `E_pq`, and a hybrid one for none before it.

A `NodeCert` takes effect only when a chain block includes it, and only from `valid_from`, which
must be at least `CHN_KEY_LEAD_EPOCHS` (4) after the including block's epoch. The lead time exists
because sessions derive `K_seq` from `xchg_key` up to 3 epochs ahead (§5.3). The newest cert with
`valid_from ≤ e` is the one in force for epoch e.

### 2.4 Committee keys

`K_com` must be identical for the 4 non-sequencing operators, or a client could give them different
keys and split their verdicts. Pairwise X25519 cannot give 4 parties one key. So each epoch has one
committee key per possible sequencer.

- For each epoch e and each operator s, `G(e, s)` is an X25519 key pair. Its private half is held
  by the nodes `(i, home(e))` for every i ≠ s, and by no one else.
- Dealer: the lowest `OpIdx` in `committee(e) \ {s}`. It generates `G(e, s)`, encrypts the private
  half to each other member under `X25519(dealer XK, member XK)` with BLAKE3 `derive_key`
  (`"vyrn v1 gkey wrap"`), and submits `CommitteeKey` to the chain.
- Each member decrypts, checks that the scalar multiplied by the base point equals the published
  public key, and signs a confirmation. The record takes effect with 3 confirmations, so one absent
  member does not block it.
- **From `E_pq`** (01 §14.20 G, KG1), for every e ≥ `E_pq`: `G(e, s)` is a hybrid pair, an X25519
  key plus an ML-KEM-768 key generated from a 64-byte seed, and `pub_key` is their `KexKey`. The
  dealer also encapsulates to the ML-KEM part of each member's exchange key and puts the 1,088 B
  ciphertext `ct` beside the wrap. The wrap key's material is the X25519 secret ‖ the ML-KEM secret
  ‖ BLAKE3(`ct`). The wrapped private half is the X25519 scalar and the ML-KEM seed (96 B, 112 B
  with the tag). Each member also checks that ML-KEM key generation from the seed gives the
  published ML-KEM key, so the dealer still cannot give members different keys. Cost: 3
  encapsulations per record and one decapsulation per member, ≤ 0.1 ms in all.

```
CommitteeKey {
    epoch: Epoch, seq_op: OpIdx, pub_key: KexKey,   // 32 B, or 1,216 B for e ≥ E_pq
    wrapped: [(OpIdx, [u8; 48]); 3],          // to the 3 other members; for e ≥ E_pq
                                              //   [u8; 1,088 + 112]: ct ‖ wrapped hybrid half
    confirms: [(OpIdx, [u8; 64]); ≥ 3],      // Ed25519 by each member's NK
}
```

`G(e, s)` for all 5 values of s is on chain at least `CHN_KEY_LEAD_EPOCHS` (4) before e. Five keys
are needed because a failover in epoch e moves the sequencer role to another operator (§3.2), and
that operator must not hold the `K_com` of its own epoch.

A byzantine dealer can leak `G(e, s)` to sequencer s. That is 2 byzantine operators, outside the
model. A byzantine dealer cannot give members different keys, because each member checks its key
against the one published key.

### 2.5 Votes

The consensus is Simplex (`07-replication.md`). Every consensus message an operator signs has this
layout, signed with `VK(op, home)`:

```
VoteMsg {
    ctx:     "vyrn      v1 vote",
    chain_id: u32,
    epoch:   Epoch,
    kind:    u8,       // 1 Notarize, 2 Nullify, 3 Finalize
    view:    u64,      // Simplex view within the epoch's instance, starts at 1
    height:  Height,   // chain height of the proposal; 0 for Nullify
    block:   Hash,     // BLAKE3 of the ChainHeader; zero for Nullify
}
```

**The one-vote rule (`INV-CHN-ONEVOTE`):** across all its nodes and keys, an operator signs for
each `(epoch, view)` at most one `Notarize`, at most one `Finalize`, and never both a `Finalize` and
a `Nullify`. These are the three conflicts Simplex defines, and each is slashable (§8).

Why the rule is per `(epoch, view)` and not per `(epoch, height)`: in Simplex an honest node can
finalize-vote block B at height h in view v while the other 4 nullify view v. View v+1 then proposes
a different block B′ at the same height h, and the same honest node votes for it. A rule keyed by
height would slash that honest node. Each view is one proposal slot, so "one vote per slot" is the
correct form of "one vote per height".

Each validator box persists a high-water mark `(epoch, view, kind, block)` to NVMe and fsyncs it
before it sends a vote. After a restart it never signs below the mark.

### 2.6 The double-sign rule across homes

An operator has 3 vote keys. Only one of its nodes is eligible in an epoch:

```
eligible(op, node_home, e) = (node_home == home(e))
```

`home(e)` comes from certified chain state (the schedule and any `HomeOverride`), never from a
clock. Rules:

1. A vote is valid only if it verifies under `VK(op, home(e))` from the `NodeCert` in force for e.
2. A vote signed by a node key of a home that is not eligible for e is invalid. If anyone submits
   it, it is `CrossHomeVote` evidence (§8), slashed lightly. It shows that an operator runs a node
   that signs outside its epoch, which is the precondition for a real double vote after a
   `HomeOverride`.
3. Conflicting votes from two keys of one operator count as a double vote by that operator.
   Attribution is to the operator, not to the key.
4. At a handoff, epoch e and epoch e+1 have different homes, different keys and separate Simplex
   instances (the instance namespace includes the epoch). The old committee signs only the
   `HandoffRecord` of e, and the new committee signs only views of e+1. They cannot conflict.

### 2.7 Genesis

```
GenesisRecord {
    chain_id:      u32,
    genesis_time:  Nanos,            // TAI; start of epoch 0 (a TYO epoch boundary, 00:00 TYO)
    operators:     [OperatorEntry; 5],  // OIK, BK, GK, client_kind, name hash
    node_certs:    [NodeCert; 15],
    committee_keys:[CommitteeKey; 5 × CHN_KEY_LEAD_EPOCHS],   // epochs 0–3
    params:        ParamSet,         // every governance parameter, §2.10 and §17
    assets:        [AssetEntry],     // asset id, L1 token address, decimals
    books:         [BookEntry],      // book id, base, quote, tick size, lot size, book group
    bridge:        { l1_chain_id: u64, contract: [u8; 20], deploy_block: u64 },
    sigs:          [(OpIdx, [u8; 64]); 5],   // all 5 OIKs: genesis is 5-of-5
}
genesis_hash = BLAKE3(derive_key("vyrn      v1 genesis", canonical_encoding(GenesisRecord)))
```

Genesis is 5-of-5 because no earlier set exists to certify it. Every client is configured with
`genesis_hash`. The bridge contract is deployed first with the 5 bridge keys and `chain_id`, and
the genesis record names its address. Chain height 0 is the genesis. Epoch 0 opens with an opening
auction like every other epoch.

### 2.8 Bonds

| Bond | Amount (budget, governance parameter) | Posted by | Locked |
|---|---|---|---|
| Operator bond | `CHN_OPERATOR_BOND` = 20,000,000 USDC | each operator | from joining until `CHN_UNBOND_EPOCHS` (63 epochs, 21 days) after leaving |
| Sequencer bond | `CHN_SEQ_BOND` = 10,000,000 USDC | the sequencing operator of e | from e − 4 until e + `CHN_EVIDENCE_EPOCHS` (42 epochs, 14 days) |
| Session bond | ≥ `CHN_SESSION_BOND_MIN` = 1,000 USDC, and ≥ the session's rate-based minimum (§5.9) | the account opening the session | from open until the close is final plus `FIN_GATE_BLOCKS` |

Bonds are chain state, held in the chain's USDC balances of a reserved bond account per operator.
They come from deposits through the bridge like any balance. Slashing moves bond balance by state
transition. No L1 action is needed to slash, because the funds already sit behind the bridge.

An operator that cannot post its sequencer bond by e − 4 is skipped in the schedule for e (§3.1).

Why the unbonding period is 21 days: it must exceed the evidence window (14 days) so that every
slashable fault can be proved while the bond is still locked. It also exceeds the light-client
weak-subjectivity period (§10.4).

### 2.9 Membership changes

- The set always has exactly 5 operators in v1. A change replaces one operator with another.
- A change is a governance action (§2.10) with an activation epoch `e_act`. It takes effect only at
  the start of `e_act`, which is an epoch boundary.
- The incoming operator must, before `e_act − CHN_KEY_LEAD_EPOCHS`: post the operator bond, have
  its 3 `NodeCert`s included, take part in the `CommitteeKey` records for epochs ≥ `e_act`, and
  have its validator boxes in every home following the log.
- The outgoing operator stops voting at `e_act`. Its bonds unbond after `CHN_UNBOND_EPOCHS`.
- Because `home(e)` rotates, the incoming operator's first active epoch is `e_act` in `home(e_act)`.
  It needs its node there to be synced at that moment, not earlier.

**Jailing.** An operator that is slashed for equivocation or a double vote is jailed at the
boundary where the slash applies. A jailed operator's votes do not count, it is skipped as
sequencer and as leader, and it does not receive committee keys for later epochs. The set then has
4 counting operators and still needs `Q_CHAIN = 4` signatures. So until governance replaces the
jailed operator, the chain tolerates 0 further faults for liveness. Safety is unchanged: 4 honest
signatures out of 4 are still required. This is a residual risk (§15). Governance must start a
replacement within `CHN_JAIL_REPLACE_EPOCHS` (9).

### 2.10 Governance

Governance is a set of actions signed by 4 of the 5 operator identity keys.

```
GovAction {
    ctx: "vyrn      v1 gov", chain_id: u32, gov_nonce: u64,
    action: GovKind, activation: Epoch,
    sigs: [(OpIdx, [u8; 64]); ≥ 4],      // Ed25519 by OIK
}
GovKind = SetParam { id: u16, value: u128 } | ReplaceOperator { out: OpIdx, entry: OperatorEntry }
        | Upgrade { proto: ProtoVer, release_hash: Hash } | AddBook { .. } | AddAsset { .. }
        | Jail { op: OpIdx } | Unjail { op: OpIdx } | HaltBook { book: BookId } | ResumeBook { .. }
        | HomeOverride { epoch: Epoch, home: HomeCode } | RotateOperatorKey { op, new_oik }
```

Two classes:

| Class | Actions | Delay |
|---|---|---|
| **Tightening** (reduces power or risk) | `Jail`, `HaltBook`, lower any cap, raise any bond, `HomeOverride` for an epoch that has not started | effective at the next boundary (§4.6), no timelock |
| **Loosening** (everything else) | parameters that raise caps or lower bonds, `ReplaceOperator`, `Upgrade`, `AddBook`, `AddAsset`, `Unjail`, `ResumeBook`, `RotateOperatorKey` | `activation ≥ current epoch + CHN_GOV_TIMELOCK_EPOCHS` (9 epochs, 72 h) |

Why 72 h: the worst-case exit is a withdrawal request, a 60 s batch, an L1 post, a 1 h challenge
period and an L1 claim, about 1.5 h in total (§6.5). A user who disagrees with an approved action
can leave well before it takes effect.

Governance cannot move a user balance, mint an asset, or change a past block. No `GovKind` does
those things, and an `Upgrade` that adds one is visible in the 72 h before it activates.

A stolen `OIK_i` is handled by the other four: they `Jail` operator i (tightening, immediate) and
then rotate its key or replace it (loosening, timelocked). A `RotateOperatorKey` signed by the old
key alone is not valid. It needs 4 of 5 like any other action.

## 3. The sequencer role

### 3.1 Schedule

```
seq_op(e) = first i in [e mod 5, e+1 mod 5, …, e+4 mod 5] such that
            i is not jailed, i is bonded, and i posted CHN_SEQ_BOND for e by e − 4
```

The schedule is a pure function of chain state at e − 4. Clients and validators compute it four
epochs ahead. Since gcd(3, 5) = 1, the pair (home(e), seq_op(e)) cycles through all 15
combinations every 15 epochs. No operator always sequences the same session of the day, so no
operator always faces the same flow.

One sequencer operator serves every book of the home in its epoch. Why not a different operator per
book: the Simplex leader set excludes the sequencing operator (§4.3). With several sequencing
operators the leader set would shrink below what liveness needs.

### 3.2 Failover order

`08-epochs.md` and `07-replication.md` own the failover protocol (`FAILOVER_SILENCE_MS` = 2,
`FAILOVER_TARGET_MS` = 20). This chapter fixes only who takes over and which keys apply:

```
next_seq(e, s) = first i in [s+1, s+2, s+3, s+4] mod 5 that is eligible for e and has not
                 already been sequencer in e
```

| After a failover from s to s′ | Value |
|---|---|
| Book blocks are signed by | `SK(s′, home(e))` |
| Packets are checked on the fast path with | `K_seq(e, s′)` (§5.3) |
| `tag_com` is checked with | `K_com(e, s′, i)`, held by committee(e) minus s′. That set includes s. |
| Simplex leaders | committee(e) minus s′ |
| s may sequence again in e | no |

Operator s holds `K_com(e, s′, ·)` but not `K_seq(e, s′)`, so the key split still holds.
Clients precompute `K_seq(e, i)` for all 5 values of i, so a failover needs no client transaction.

**The standby (01 §14.4).** Failover promotes the warm standby: the F2 sequencer box of
s′ = `next_seq(e, s)`, which replays the order stream and has derived `K_seq(e, s′)` for every
session from `XK(s′, home(e))`. It never promotes a validator box, so the client split and the 5
voters survive. **No sequencer box, live or standby, of any operator ever holds a `G` private
half.** `G` private halves are loaded only on validator boxes and commit boxes. So s′ never holds
`K_com(e, s′, ·)`, although its validator box holds `G(e, s)`. A same-operator standby (an F2 box of
s itself) would keep `K_seq(e, s)` and `SK(s, home(e))` and would still receive no `G` key, because
`K_com(e, s, ·)` stays with the four other members. v1 does not use it: a byzantine s controls both
of its boxes, so promoting its own standby would not remove the fault.
The client learns the new sequencer from the failover notice (`04-protocol.md`) and switches the
key it uses for `tag_seq` and the chain it uses for `tag_com`.

### 3.3 Duties

The sequencing operator must:

1. Run `vyrn-seq` for every book of the home for the whole epoch (`05-engine.md`).
2. Check `tag_seq` with `K_seq(e, s)` on every packet, and close the session on the first failure
   from the bound address (01 §4, §12.5).
3. Tag every response with `K_out(e, s)` (§5.3).
4. Emit one book block per book per `BLOCK_NS`, with `seq_sig` (§3.4).
5. Apply every item at the first boundary after its chain block is notarized or final, never after
   its deadline, and obey `INV-CHN-TXGATE` (§4.6).
6. Suspend a session when `CHN_TAGFAULT_QUORUM` (2) distinct committee members report a `tag_com`
   failure on it (§5.8), and log the suspension.
7. Stop at the end of the epoch, emit the `HandoffRecord` and hand off (`08-epochs.md`).
8. Keep its validator box voting. The validator box is a separate box (`INV-CHN-SPLIT`).

The sequencing operator must not lead a Simplex view, hold any `G(e, s)` private key, or run the
data node that a client's data copy goes to (§13.3).

### 3.4 seq_sig

```
seq_sig = Ed25519_sign(SK(s, home(e)),
                       derive_key("vyrn      v1 seqsig", encode(BlockHeader without seq_sig)))
```

One signature per book per millisecond costs about 1,000 signatures per second per book. It runs on
order-stream core A (core 4, 07 §6.2) in slices, off the 1 µs path. Before it signs height h,
`vyrn-seq`'s control thread (core 51, 01 §10) persists
`(book, h, header hash)` as its high-water mark and never signs a different header at or below it.
That mark makes equivocation impossible for an honest sequencer, even across a crash: an honest
sequencer that crashes is failed over and does not sign again in the epoch.

### 3.5 What the sequencer cannot do

| Attempt | Why it fails |
|---|---|
| Forge a client packet | It lacks `K_com`. The committee excludes the packet and its fills are busted (§5.9). |
| Sign two histories for one height | Two valid `seq_sig`s for one `(book, height)` are evidence; the bonds are slashed (§8). |
| Keep trading after the handoff | A header of epoch e above the certified `last_height` is `FenceViolation` evidence. |
| Censor a client | The client uses the forced path; the leaders are other operators (§7). |
| Delay a transaction's effect | The boundary is fixed by finalized chain blocks, not by the sequencer (§4.6). A halt that continues after the gate's condition holds counts as silence and starts a failover (§4.6). |
| Reorder a client's packets against others | It can. That is front-running, capped in §13. |

## 4. State model

### 4.1 Two levels of state

State has two levels. The **chain level** is ordered by chain blocks and changes at low rate. The
**book level** is ordered by the order stream, lives in lanes while the book is live, and changes at
up to 1B messages per second.

| Level | Object | Key | Fields | Writer while live |
|---|---|---|---|---|
| chain | Account | `AccountId` | `owner: OwnerKey`, `nonce: u64`, `exit_address: [u8; 20]`, `created: Height` | chain state machine |
| chain | Free balance | `(AccountId, AssetId)` | `free: u128`, `pending_withdraw: u128` | chain state machine |
| chain | Session | `SessionId` | account, book group, `x25519_pub`, `sign_pub`, bound address, bond, epochs, anchors, status | chain state machine (open, close, suspend results come from lanes) |
| chain | Validator set | `OpIdx` | `OperatorEntry`, `NodeCert`s, bonds, jail flag | chain state machine |
| chain | Committee keys | `(Epoch, OpIdx)` | `CommitteeKey` | chain state machine |
| chain | Bridge | — | deposit nonce credited, pending `L1Attest`s, withdrawal queue, L1 posts and their status | chain state machine |
| chain | Governance | — | `ParamSet`, pending `GovAction`s, `gov_nonce`, protocol version table | chain state machine |
| chain | Funds | — | insurance fund, fee pool per epoch, bust escrow | chain state machine |
| book | Allocation | `(AccountId, BookId, AssetId)` | `available: u128`, `reserved: u128` | the account's lane (01 §12.2) |
| book | Resting order | `(LaneId, Handle)` | account, side, tick, open qty, rx_ts | the account's lane; filled qty by the BBO core |
| book | Lane session state | `SessionId` | `K_seq`, `K_out`, bound address, `pkt_seq` window, suspended flag | the session's lane |

`OwnerKey = Ed25519([u8; 32]) | Secp256k1([u8; 20])` (an EVM address)
`| Hybrid(PubKey)` (scheme 1, from `E_pq`; §6.8). An account is created by its
first credited deposit, which names the owner (§6.3). `AccountId`s are assigned in credit order,
starting at 1. The lane of an account in a book group is assigned by `10-accounts-risk-md.md`.

**Allocations are escrow (01 §12.4).** `Allocate` moves an amount from the free balance into a
book's allocation. From then on the lane owns that amount. The chain level does not hold a live
copy. It holds the allocation as of the last finalized book block, which every validator computes by
replay. A light client sees it every second in the SMT (§9.3).

### 4.2 How book-level state is committed

Book-level state is never written by a transaction. It is a pure function of the finalized order
stream and the items applied at boundaries (`INV-DET`). So:

- **per book block:** the order stream of the block is final when the chain block that includes it
  is final. From that moment every byte of book state at the end of that block is determined.
- **per second:** validators publish the SMT root of all allocations and the lattice hash of all
  resting orders (§9).

No validator signs book state block by block, because computing it is the replay itself and runs
behind the live book. Signing the order is enough, and the per-second commitment lets anyone check
that the validators computed the same state.

### 4.3 The chain block

The Simplex payload in chain mode is a `ChainBlock`. One view proposes one chain block. A chain
block wraps the book blocks that the leader holds and that follow the last included ones.

```
ChainHeader {
    chain_id:    u32,
    epoch:       Epoch,
    height:      Height,     // chain height: parent.height + 1. Never resets.
    view:        u64,
    parent:      Hash,       // BLAKE3 of the parent ChainHeader
    leader:      OpIdx,
    books_root:  Hash,       // Merkle root over BookEntry, sorted by book
    items_root:  Hash,       // Merkle root over the item list, in order
    excl_root:   Hash,       // Merkle root over the ExclusionLists, sorted by (book, book height)
    log_hash:    Hash,       // §9.2
}
BookEntry { book: BookId, first: Height, last: Height, last_header: Hash }   // book heights
ChainBlock { header: ChainHeader, books: [(BookEntry, [BlockHeader])], items: [Item],
             excl: [ExclusionList] }
```

`BlockHeader.height` (01 §6.6) is the **book height**: one per book per millisecond. `ChainHeader.height`
is the **chain height**. With one hot book, a chain block usually carries exactly one book block, and
the two heights advance together. A chain block that carries no book block is valid; it can still
carry items.

**Leader schedule.** `leaders(e) = committee(e)` minus the current sequencing operator, minus jailed
operators, in `OpIdx` order. `leader(e, v) = leaders(e)[v mod len]`. A leader is always a `K_com`
holder, so it can always compute the exclusion lists of the book blocks it proposes.

**What a voter checks before it notarizes** (in this order; `07-replication.md` gives the generic
checks):

1. `parent`, `view` and `leader` follow Simplex and the leader schedule.
2. For each book: the headers continue the last included header of that book with no gap, each has
   a valid `seq_sig` under `SK` of the current sequencer, and the voter holds every order-stream
   record and every payload they reference (`07-replication.md`).
3. Each exclusion list equals the one the voter computes (§5.7). The sequencing operator's
   validator box skips this check, because it has no `K_com`.
4. Each item that a book block h applies comes from an ancestor C of this chain block (or is a
   signed forced hint), with `lastb(C) < h`, in item order, at a boundary or at the gate-open
   point; and every lane item whose deadline `act(C, b)` (after carries) is ≤ h has been applied
   (§4.6).
5. Each item is valid against the state after the parent: signature, nonce, fee, size and rate
   limits, and not already included.
6. At most `CHN_MAX_ITEMS` (500) items and `CHN_MAX_ITEM_BYTES` (256 KiB) of items.
7. `log_hash` and the three roots are recomputed and equal.

### 4.4 The transaction path

Non-order actions use their own path, which never touches the 1 µs path.

- **Transport:** QUIC (RFC 9000) to `CHN_TX_PORT` on any node of any home. A node outside the active
  home forwards to the active committee. The NIC flow filter of a sequencer box never sees this
  port.
- **Mempool:** a validator box that accepts an item gossips it to the next 3 leaders in the
  schedule. A leader includes items in arrival order, up to the caps.
- **Envelope:**

```
TxEnvelope {
    version: u8 (= 1), kind: u8, body_len: u16,
    signer:  SignerRef,       // Account(AccountId) | Session(SessionId) | Node(OpIdx, HomeCode)
                              //   | Operator(OpIdx) | Anyone
    nonce:   u64,             // per signer; must be last + 1
    max_fee: u64,             // in USDC micro-units; the fee charged is ≤ this
    body:    [u8; body_len],
    scheme:  u8,              // 0 Ed25519, 1 secp256k1 (EIP-712), 2 hybrid Ed25519 + ML-DSA-44 (§6.8),
                              //   3 hybrid Ed25519 + ML-DSA-65 (01 §14.20 scheme 2)
    sig:     [u8; 64, 65, 2,484 or 3,373],
}
```

- **Signatures:** Ed25519 signs `derive_key("vyrn v1 tx", encode(envelope without sig))`.
  Envelope schemes 2 and 3 sign the same digest under 01 §14.20 A (both parts over
  `scheme ‖ digest`, with the `SigScheme` code 1 or 2). The envelope scheme must match the signer's
  key: scheme 3 is the only one an `Operator(OpIdx)` signer can use once its `OIK` is hybrid
  ML-DSA-65 (§2.2), so `NodeCert` submissions, bond actions and governance stay signable after the
  switch.
  secp256k1 signs the EIP-712 digest of the same fields, with the domain
  `{name: "VYRN", version: "1", chainId: l1_chain_id, verifyingContract: bridge}`, so that EVM
  wallets can show what they sign.
- **Rate:** `CHN_TX_RATE` (10 per second) per signer, enforced at inclusion. The whole path is sized
  for 500 items per chain block, 500k per second (budget). Real load is orders of magnitude lower.

### 4.5 Item kinds

| Code | Item | Signer | Applies in | Effect |
|---|---|---|---|---|
| 0x01 | `SessionOpen` | wallet | chain, then lane | Registers a session (§5.2). Locks the bond. Installs keys in the lane at the boundary. |
| 0x02 | `SessionClose` | wallet or session key | lane, then chain | Cancels the session's resting orders, closes it, releases the bond after the close is final. |
| 0x03 | `SessionRebind` | session key | lane | Changes the bound source address. |
| 0x04 | `Allocate` | wallet or session key | chain, then lane | free → allocation of one book. |
| 0x05 | `Deallocate` | wallet or session key | lane, then chain | allocation → free, if `available` covers it; else rejected in the lane. |
| 0x06 | `Move` | wallet or session key | lane, chain, lane | `Deallocate` on one book, then `Allocate` on another (§4.7). |
| 0x07 | `Withdraw` | wallet | chain | free → `pending_withdraw`, queued for the next L1 post (§6.5). |
| 0x08 | `CancelWithdraw` | wallet | chain | Undoes a `Withdraw` that is not yet in an L1 post. |
| 0x09 | `SetExitAddress` | wallet | chain | Sets the L1 address used by the escape hatch (§6.6). Rejected for an `exit_frozen` account (§6.8). |
| 0x0A | `SetOwnerKey` | wallet | chain | Replaces the account's `OwnerKey`, from `E_pq` (§6.8). Never clears `exit_frozen`. |
| 0x10 | `ForcedPacket` | session key | lane | A request packet on the forced path (§7). |
| 0x20 | `L1Attest` | node key | chain | Deposits and contract events seen on L1 (§6.3). |
| 0x21 | `CommitteeKey` | node keys | chain | §2.4. |
| 0x22 | `NodeCert` | operator key | chain | §2.3. |
| 0x23 | `AnchorFault` | node key | chain | A session's anchor does not match (§5.4). |
| 0x24 | `CommitCert` | 4 vote keys | chain | Puts a state commitment on chain (§9.5). |
| 0x25 | `HandoffTimeout` | vote keys | chain | Quorum attestation of a missing handoff (§8.4). |
| 0x26 | `ReadySignal` | node key | chain | Upgrade readiness (§14.2). |
| 0x30 | `Evidence` | anyone | chain | A slashing proof (§8). |
| 0x31 | `GovAction` | 4 operator keys | chain | §2.10. |
| 0x32 | `EvidenceCommit` | anyone | chain | The BLAKE3 hash of an `Evidence` encoding. Locks classical evidence before `E_pq` so it still slashes after the switch (§8.1 item 2a). No effect otherwise. |

Items in one chain block are applied in list order. A leader orders them by arrival, so a leader can
reorder items within one block. Items do not trade, so the value of reordering them is small, and
§13 covers the orders that do trade.

### 4.6 Positioning: the boundary rule

An item that touches a book must take effect at a point that is deterministic and that replay can
check. The sequencer chooses the point and logs it. Consensus fixes the latest allowed point:

```
lastb(C, b)  = the highest book-b height included in chain block C or in any ancestor of C
act(C, b)    = lastb(C, b) + FIN_GATE_BLOCKS + 1        // D + 1 = 9: the deadline, not the delay
```

- **Chain-only effects** of the items in chain block C apply at the end of C, in item order.
- **Lane effects** on book b apply at a **block boundary**: as the first ops of the lane in a book
  block, before any packet the lane processes in it. Several items for one lane apply in item order.
  The sequencer logs each applied item as an `ItemRecord` in the order stream (§17.2), so replay
  applies it at the same op. An honest sequencer uses the first boundary after it holds:
  - the **notarization** of C, for a self-authenticating lane item: `ForcedPacket`, `SessionRebind`,
    `SessionClose`, `Deallocate` and the first half of `Move`. Each carries the signature of its
    session or wallet and a nonce, so it is valid in any position, and a copy that C's branch later
    loses is a no-op when it is included again (nonce or `pkt_seq` dedupe).
  - the **finalization** of C, for an item whose lane effect needs a chain effect first (`SessionOpen`,
    `Allocate`, the second half of `Move`) and for busts and suspensions (§5.8, §5.9), whose chain
    block is the one that includes the exclusion list.
- **The deadline.** Every lane effect of C is applied at or before the first boundary of book block
  `act(C, b)`. A voter that finds one missing there fails check 4 (§4.3), treats the sequencer as
  silent (07 failover) and submits `Censorship` evidence (§8.2). The new sequencer applies the
  missing items first (01 §14.0 fact 3).
- **Lane results flow back.** A lane result that changes chain state (a `Deallocate` that succeeded,
  a session that closed) applies at the end of the first chain block that includes the book block in
  which the lane produced it.
- **Item work per lane is capped.** Item ops run on the lane core, ahead of the block's packets. A
  lane applies at most `CHN_ITEM_OPS_PER_BLOCK` (16) item ops at one boundary, ≤ ~0.64 µs (budget);
  the rest carry, in order, to the next boundary, and the deadline moves with them. Deadline
  admission (01 §14.1) sheds any packet they would make late, and B3 counts it against the `BUSY`
  budget. So no item, however large, breaks the 1 µs.

```
book height  ...  x     x+1     x+2     x+3     x+4    ...    x+9
order stream ────┼──────┼───────┼───────┼───────┼─── ... ─────┼────►
                 │ C includes book blocks ≤ x, plus items (proposed at ~x+1.6)
                 │        │ C notarized: forced packets, rebinds, closes, deallocates apply at x+3
                 │                │ C final: opens, allocates, busts apply at x+4
                 │                                            │ act(C) = x+9: the deadline; a missing
                 │                                            │ item is censorship → failover
TXGATE: the sequencer applies no op of block h until it holds a finalization of book block h − 9.
```

**`INV-CHN-TXGATE` (01 §14.9):** the sequencer never runs more than D = `FIN_GATE_BLOCKS` = 8
closed blocks ahead of finality, the count 07 §6.8 uses. It applies no op of book block h (no
item, no packet, no step) until it holds a finalization certificate for a chain block that
includes book block h − D − 1. Finalize votes go to the
live and the standby sequencer boxes as well as to the voters, so the sequencer holds the
certificate at hop 4 (§4.8). The gate also makes every deadline reachable: an item with deadline h
comes from a chain block C with `lastb(C) = h − D − 1`, and C is final once h − D − 1 is.

**The halt.** If the certificate for h − 9 is missing at h's boundary, the book halts instead of
issuing fills that cannot be final within 10 ms:

- Order-stream core A (core 4) asks for a `Control` step (01 §14.10) with sub-code 1, *halt*, and
  the BBO core logs it. Every lane answers every packet
  with `Reject BOOK_HALTED` (detail 1 = gate) within the 1 µs and logs it as a `PacketRecord` with
  `flags.SHED`, as deadline admission does. A shed record applies nothing and does not advance the
  session's `pkt_seq`, so it needs no item, and the client resends after the halt.
- Blocks keep their 1 ms length while halted. When the certificate arrives, core 4 asks for a
  `Control` step with sub-code 2, *gate open*. Items due in the halted blocks apply at that point, in order;
  then trading resumes in the same block. Replay reads both steps from the log (`INV-DET`).
- A validator that holds the finalization of h − 9 and still sees shed records of block h or later
  `CHN_HALT_GRACE_MS` (1 ms) afterward treats the sequencer as silent. So a byzantine sequencer
  cannot use a halt to delay items or forced packets.

Consequences:

- At most D = 8 closed blocks plus the open one, ≤ 9 ms of order stream, are ever unfinalized.
  That bounds every fill that a failover could revert (`07-replication.md`).
- With at most `F` faults and the metro within its delay bound, the gate never binds: the worst case
  is 8.11 ms from block start to the certificate (§4.8), against 9.00. A halt therefore means that the network has
  left its bound or that more than `F` operators failed (01 §14.0 fact 3). The fills already issued
  (≤ 8 blocks) are on a quorum before any response (`INV-FRAME-FIRST`) and finalize when the network
  recovers. B-CHN-3 checks that the gate never binds with ≤ 1 injected fault (§19).
- Why D = 8 and not smaller: the worst in-model finality from block start (8.11 ms) must fit before
  block h + 9 opens, or the gate would halt on every slow view. Why not larger: D bounds how far
  the book runs beyond finality, and 9 ms from block start, plus the client hop (0.05) and the
  finality notice (0.05), is 9.1 ms: still inside 10 ms of the send, with no room for a tenth
  block.

### 4.7 Moving an allocation between books

`Move { account, from: BookId, to: BookId, asset, amount }` runs in three steps:

1. Chain block C includes it. At the first boundary after C is notarized (deadline `act(C, from)`),
   the lane of `from` debits `available`. If `available` is short, the move fails there and nothing
   else happens.
2. Chain block C′ includes that book block. At the end of C′ the chain credits the amount to a
   per-move transit balance and schedules the second half.
3. At the first boundary after C′ is final (deadline `act(C′, to)`), the lane of `to` credits
   `available`.

The amount is usable in `to` ~9 ms after submission and ≤ 15.7 ms (bound, §4.8). This meets
01 §12.4 ("milliseconds", never on the 1 µs path). The amount is in the transit balance between
steps 2 and 3, and the SMT shows it there.

### 4.8 Finality of every order, and item latency

**Normal-path orders.** 07 §6.6 gives the stages. CHAIN adds the `tag_com` check before the vote
and keeps the data copy out of the sequencer's facility (01 §14.16). Every row is the bound of 07 §6.6, used as the
delay bound of the model (01 §14.0 fact 3):

| Stage, from the start of the order's book block | Bound (ms, budget) | CHAIN change |
|---|---|---|
| Order → block close (an order in the block's first µs) | 1.00 | |
| Seal: roots, `seq_sig`, header out | 0.10 | |
| Hop 1: header → leader and voters | 0.80 | |
| Data lag beyond the order path | 0.71 | each session's data home is the primary data box of an operator ≠ s in its F2–F5 facility (below): two metro hops (0.80 + 0.005 batch + 0.80) against the header's seal and one hop (0.90) |
| One frame repair | 0.00 | 0.20, in parallel with the data lag: `verify` waits for the later of the two |
| `verify` completion | 0.10 | |
| `tag_com` of the last payload, exclusion list | 0.05 | 20 ns per packet, incremental; keys precomputed (§5.4) |
| Hops 2–4: proposal, notarize, finalize → `Q_CHAIN` at every voter and at the sequencer | 2.45 | |
| Vote signature checks | 0.10 | 0.15 under scheme 1 (hybrid, 01 §14.20): the ML-DSA parts run in parallel with the batched Ed25519 parts |
| **No fault** | **5.31** | was 4.85 with F1 data homes; 6.11 under scheme 1 (+0.05 vote checks, +0.75 because the leader signs its proposal after its `verify`, since the proposal carries `excl_root`; 07 §6.5a) |
| One nullified view (a byzantine or dead leader, `t_l` 2 ms + 1 hop) | +2.80 → **8.11** | the sequencer never leads, so a leader fault is a member fault; under scheme 1, 8.91 (margin 0.09 ms to the 9.00 ms gate of `FIN_GATE_BLOCKS` = 8, accepted by PQ-9, 01 §14.20; PQ-10 and PQ-11 are open) |
| or a data box redirect (07 §5.7, 3 ms in place of 0.71) | **7.60** | |
| or the sequencer is the fault | 07 failover; its seal must be final ≤ 9 ms after the last frame | |

The gate counts closed blocks (§4.6): block h must be final before block h + 9 opens, 9.00 ms
after h starts, so the margin is 0.89 ms in the worst one-fault case. With the old count (h final
before h + 8 opens, 8.00 ms) the data home outside F1 would leave −0.11 ms and halt the book at
every leader fault, which is why the count changed. The order is sent ≤ 0.05 ms before its
`rx_ts` (the client is in F1), and the finality notice reaches it ≤ 0.05 ms after the
certificate, so **every accepted order is final ≤ 8.21 ms after it is sent (9.01 ms under scheme 1), within
`FINALITY_MAX_MS` = 10**. The order's `tag_com` verdict, and so whether its fills stand or are
busted, is part of the same final block. The TESLA schedule adds nothing to this path: members
derive every `K_com` before its interval (§5.4), and disclosure (§5.10) comes seconds after
finality.

**Data placement (01 §14.16).** A data home is never in the sequencer's facility, F1 (07 §5.1):
if F1 held both, one facility loss would lose both copies of the packets in flight and revert
their fills. So in CHAIN each operator runs its primary data box in the operator's F2–F5 facility
and its backup in another of F2–F5. No data box in F1 is ever a primary home. Session σ's data home
is the primary data box of `data_op(e, σ)`, the first operator in `[σ mod 5, …]` that is not s. Its
timestamps stay independent of s (§13.3). The cost is the 0.71 ms data lag in the table above,
which the closed-block gate absorbs. 03 and 07 own the boxes.

**Items.** The bounds below place one fault where it costs most: a skipped or nullified view. Hop δ
= 0.8 ms, a view ≤ 2δ = 1.6 ms, and an item reaches the leaders ≤ 2δ after submission (a forced
packet ≤ δ, because the client sends it to all 4 members).

| Item | Takes effect | Typical (ms from submission) | Bound (ms, budget) |
|---|---|---|---|
| `Withdraw`, `CancelWithdraw`, `SetExitAddress`, governance, evidence, attestations | end of C, final with C | ~4 | 8.6 |
| `SessionOpen` (`SessionId` in the receipt) | end of C | ~4 | 8.6 |
| `SessionOpen` keys, `Allocate` | lane, first boundary after C is final | ~5.5 usable, ~9 final | 9.6 usable, 14.9 final |
| `SessionRebind`, `SessionClose`, `Deallocate` debit | lane, first boundary after C is notarized | ~4.5 usable, ~8 final | 8.7 usable, 14.0 final |
| `Deallocate` credit to free, close's bond release | end of C′, which includes that book block | ~9 | 15.2 |
| `Move` | lane of `to` | ~9 usable, ~13 final | 15.7 usable, 21.1 final |
| `ForcedPacket`, honest sequencer | the hint (§7.1), or the boundary after C is notarized | ~4 executed, ~7.5 final | final ≤ 10 (§7.4) |
| `ForcedPacket`, censoring sequencer | the new sequencer's first block | — | final ≤ deadline + `FAILOVER_TARGET_MS` + `FINALITY_MAX_MS` ≈ 41 |

Every item has the same hard deadline, `act(C, b)`, ≤ 8 ms after C's proposal. A sequencer that
misses it is replaced.

## 5. Authentication at 1B messages per second

### 5.1 Why not a signature per packet

Every packet must be attributable to a client, by a check that 4 validators can repeat. A signature
per packet is the obvious answer, and it does not fit.

| Option | Verify cost per packet | Cores per validator at 145.5M packets/s (`WL-REF`, 02 §5.2) | Bytes per packet |
|---|---|---|---|
| Ed25519 per packet | ~20 µs (budget planning figure: "tens of µs"); batch verification ~2× better | ~2,900 (~1,450 batched) | +64 |
| secp256k1 per packet | slower than Ed25519 | > 2,900 | +65 |
| Two SipHash-2-4 tags (this design) | 20 ns per tag (budget) | 2.9 for `tag_com` (budget 4 with margin) | +16 |

The sequencer has 1 µs for the whole packet, and one Ed25519 verify alone is about 20 times that
budget. A validator would need well over a thousand cores just to verify. The two-tag scheme costs
~3 cores and keeps the property that matters: no single byzantine operator can forge a packet.

### 5.2 Session open

```
SessionOpen {                               // TxEnvelope kind 0x01, signed by the wallet
    account:        AccountId,
    book_group:     u16,
    x25519_pub:     [u8; 32],              // fresh per session; never reused
    sign_pub:       [u8; 32],              // Ed25519 session signing key (forced path, small txs)
    bound_addr:     { family: u8, ip: [u8; 16], port: u16 },
    bond:           u64,                    // USDC micro-units
    max_msgs_per_s: u32,                    // the session's rate limit (04-protocol.md)
    first_epoch:    Epoch,
    n_epochs:       u8,                     // 1 ..= CHN_SESSION_MAX_EPOCHS (3)
    anchors:        [[Hash; 5]; n_epochs],  // A(e, s) for each epoch and each possible sequencer
    kem_cts:        [[[u8; 1088]; 10]; n_pq], // per epoch ≥ E_pq in range: ct_seq(e, s) for s = 0..4,
                                              //   then ct_com(e, s) for s = 0..4 (§5.3)
}
```

Validity, checked against the state after the parent chain block:

1. The wallet signature verifies against the account's `owner`.
2. `first_epoch ≥ current epoch` and `first_epoch + n_epochs − 1 ≤ current epoch + 3`. Every
   `G(e, s)` and every `NodeCert` that the session needs are already on chain (`CHN_KEY_LEAD_EPOCHS`
   = 4).
3. `x25519_pub` is not a low-order point and is not used by any other session, open or closed.
4. `bond ≥ max(CHN_SESSION_BOND_MIN, CHN_BOND_PER_MSGRATE × max_msgs_per_s)` and the free balance
   covers the bond plus the fee.
5. `n_pq` is the number of epochs in `[first_epoch, first_epoch + n_epochs − 1]` with
   `EpoConfig(e).sig_scheme` ≥ 1, and `kem_cts` holds exactly those epochs, in order (01 §14.20
   KG1). `E_pq` is scheduled under the 72 h timelock (9 epochs), more than a session's 3, so the
   wallet always knows it. Each ciphertext is exactly 1,088 B; a ciphertext that ML-KEM would reject
   still decapsulates (KG3) and only breaks the session's own keys. Size: ≤ 32,640 B for 3 epochs,
   within the envelope's 16-bit `body_len`; 8 fit in `CHN_MAX_ITEM_BYTES`.

The session gets the next `SessionId` at the end of the chain block C that includes it. Its keys
reach the lane of each book b of the group at the first boundary after C is final: ~5.5 ms after
submission, ≤ 9.6 ms (bound, §4.8), and never later than `act(C, b)`.
The client learns its `SessionId` from the transaction receipt (§10.3). A session expires at the end
of `first_epoch + n_epochs − 1`. A client that trades continuously opens its next session an epoch
before the current one expires.

Why 3 epochs at most: a session derives keys from `NodeCert`s and committee keys that must already
exist. With a 4-epoch key lead, 3 epochs is the longest lifetime that never needs a key from the
future. One day is also a natural rotation period for trading keys.

### 5.3 Key derivation

All derivations use BLAKE3 `derive_key(context, material)` (01 §4). `le(e)` is the epoch as 4
little-endian bytes. `x` is the session's X25519 private key. For e ≥ `E_pq` the wallet
encapsulates to the ML-KEM part of `XK(s, home(e))` and of `G(e, s).pub`, which gives the
ciphertexts `ct_seq(e, s)` and `ct_com(e, s)` of §5.2 and the secrets `m_seq(e, s)` and
`m_com(e, s)`. The node holding the private half gets the same secret by decapsulation. Before
`E_pq` the `m` and `ct` terms are absent (01 §14.20 G).

```
P_seq(e, s)    = X25519(x, XK(s, home(e))) ‖ m_seq(e, s) ‖ BLAKE3(ct_seq(e, s))   // client ↔ sequencer node of s
K_seq(e, s)    = derive_key("vyrn      v1 session", P_seq ‖ x25519_pub ‖ le(e) ‖ [s] ‖ "seq")[0..16]
K_out(e, s)    = derive_key("vyrn      v1 session", P_seq ‖ x25519_pub ‖ le(e) ‖ [s] ‖ "out")[0..16]

P_com(e, s)    = X25519(x, G(e, s).pub) ‖ m_com(e, s) ‖ BLAKE3(ct_com(e, s))      // client ↔ committee(e) minus s
head(e, s)     = derive_key("vyrn      v1 kcom head", P_com ‖ x25519_pub ‖ le(e) ‖ [s])   // 32 B
c(e, s, N)     = head(e, s)
c(e, s, k − 1) = BLAKE3(c(e, s, k))          for k = N, N−1, …, 1
A(e, s)        = c(e, s, 0)                                       // the anchor, on chain
K_com(e, s, i) = derive_key("vyrn      v1 kcom", c(e, s, i))[0..16]    for i = 1 ..= N
```

`N = CHN_TESLA_N = 28,800`, the number of 1 s intervals in an 8 h epoch.

| Party | Can compute | Because it holds |
|---|---|---|
| Client | everything | `x` |
| Sequencer node of s in home(e) | `K_seq(e, s)`, `K_out(e, s)` | `XK(s, home(e))` private |
| Node `(i, home(e))`, i ≠ s | `head(e, s)`, every `c(e, s, ·)`, every `K_com(e, s, ·)` | `G(e, s)` private |
| Anyone | `A(e, s)`; `c(e, s, j)` for j ≤ i after `c(e, s, i)` is disclosed | chain state, disclosures |

`K_seq` and `K_com` use the 128-bit SipHash key size of 01 §4. `K_out` tags responses (01 §6.3).
`INV-CHN-KEYSPLIT`: for every (session, e, s), no operator other than s can compute `K_seq(e, s)`,
and operator s cannot compute any `K_com(e, s, ·)` before its disclosure.

### 5.4 TESLA intervals and anchors

Interval index of a book block, with `h0(e, b)` the first book height of book b in epoch e:

```
interval(e, b, h) = min(N, 1 + (h − h0(e, b)) / CHN_TESLA_BLOCKS)       // CHN_TESLA_BLOCKS = 1000
```

The interval is counted in book blocks, not in clock time, so it is deterministic and the sequencer
cannot move it. A book block is 1 ms, so one interval is about 1 s. A failover leaves a gap of
about 20 ms, so the interval drifts behind wall time by about 20 ms per failover.

**Acceptance window.** A packet in book block h passes `tag_com` if the tag verifies under
`K_com(e, s, j)` for some j in {i, i − 1, i + 1} ∩ [1, N], where i = `interval(e, b, h)`. The
validator tries i first, then i − 1, then i + 1, so only failing packets cost more than one SipHash.

**Key schedule on the validator box.** `K_com(e, s, i)` sits `N − i` hashes below the chain head,
so computing it on demand costs up to 28,800 BLAKE3 calls (~1.5 ms) per session. That must never
happen on the voting path. Each member keeps, per (session, e, s) for the 4 values of s it holds,
a fractal hash-chain traversal state (Jakobsson; ⌈log2 N⌉ = 15 pebbles, ≤ 15 BLAKE3 calls per
interval step), seeded by the anchor-check walk below. During interval i it derives
`K_com(e, s, i + 2)`, so the keys for i − 1, i and i + 1 are always in a 3-entry ring when a packet
arrives. Cost (budget): 100k sessions × 4 × ~0.8 µs ≈ 0.3 core per second and ~190 MB. A
failover to s′ needs no recomputation, because the ring for s′ is already warm.

**The client picks i** from the latest book height it has seen (every market-data packet carries it,
`10-accounts-risk-md.md`) plus the milliseconds elapsed since. The ±1 window tolerates ±1 s of
error, which covers clock error, network delay and failover drift.

**Anchor check.** When a chain block includes a `SessionOpen`, each node `(i, home(e))` with i ≠ s
computes `head(e, s)`, hashes it N times and compares the result with `A(e, s)`. That is 28,800
BLAKE3 calls on 32 bytes, about 1.5 ms per (session, e, s) (budget), and it runs on the commit box
long before epoch e starts. On a mismatch the node submits `AnchorFault { session, e, s, node sig }`.
When `CHN_ANCHORFAULT_QUORUM` (2) distinct operators have submitted one, the session is marked
`NoKey(e, s)`. In any block of epoch e signed by sequencer s, the lane rejects its packets with
`SESSION_CLOSED`, and the exclusion list marks any that slip through with reason `NO_KEY`. One
byzantine operator cannot mark an honest session, because the quorum is 2 and honest verdicts agree.

### 5.5 Which check runs where

| Where | Check | Key | Cost (budget) | On failure |
|---|---|---|---|---|
| Sequencer lane, on the 1 µs path | `tag_seq` | `K_seq(e, s)` | 20 ns per packet | From the bound address: close the session (`BAD_MAC`). From another address: drop and count (01 §12.5). |
| Validator box of each committee member except s | `tag_com` | `K_com(e, s, i ± 1)` | 20 ns per packet; 2.9 cores at 145.5M/s, budget 4 | Exclusion list entry, `TagFault` to the sequencer (§5.8). |
| Validator box of operator s | none | — | — | Votes on the leader's exclusion list without checking it (§5.6). |
| Any third party, after disclosure | `tag_com` | disclosed `K_com` | 20 ns per packet | `WrongExclusion` evidence (§8.2). |

No validator checks `tag_seq`, because no validator holds `K_seq`. The order stream contains only
packets that passed it, and an honest sequencer guarantees that. A byzantine sequencer can insert
packets that fail it; they still need a valid `tag_com`, which is the point of the scheme.

### 5.6 Security argument

**Claim 1 (no single-operator forgery).** A packet of session σ that is not excluded in a finalized
book block was produced by σ's client, or by a coalition of the sequencing operator s and at least
one other operator.

- A packet enters the order stream only through s. An honest s accepts only valid `tag_seq`, and
  only the client and s can compute `K_seq(e, s)`.
- A packet is not excluded only if it has a valid `tag_com` (Claim 3). Only the client and the 4
  committee members other than s can compute `K_com(e, s, j)`. A key is disclosed only after every
  block that could accept it is final (§5.10).
- So a forgery needs s (to put it in the stream) and a member (to tag it): 2 byzantine operators,
  and 2 > `F` = 1. The forced path does not weaken this, because forced packets carry an Ed25519
  signature by the session key instead of tags (§7.2).

**Claim 2 (honest members agree).** The verdict on a packet is a pure function of the packet bytes,
the session's `x25519_pub` (chain state), `G(e, s)` (one key that every member checked against one
public key, §2.4) and the book height. So every honest member reaches the same verdict on every
packet. A client cannot split them, because it chooses none of these inputs per member.

**Claim 3 (certified exclusion lists are correct).** A finalized chain block carries 4 signatures.
Only one signer, s, is not a committee member, so at least 3 signers are members. At most 1 is
byzantine, so at least 2 honest members recomputed the list and found it equal to theirs. By
Claim 2 the list is the honest verdict.

**Claim 4 (liveness with one fault).** If s is faulty, failover replaces it (§3.2). If one member
is faulty, the 3 honest members plus the blind vote of s make 4.

**Blind votes are safe.** An honest s may sign a chain block whose list a byzantine leader got
wrong. By Claim 3 that block cannot gather 4 signatures, so the blind vote never finalizes a wrong
list. A blind vote is never slashable.

### 5.7 The exclusion list

```
ExclusionList { book: BookId, height: Height, entries: [ExclEntry] }   // one per included book block
ExclEntry     { rec: u32,          // index of the PacketRecord in the book block, in record order
                session: SessionId, pkt_seq: u32,
                reason: u8 }       // 1 BAD_COM, 2 SESSION_DEAD, 3 NO_KEY
```

Every included book block has a list, empty when nothing is excluded. Entries are sorted by `rec`.
`excl_root` in the `ChainHeader` is the Merkle root over the encoded lists, so a vote on the header
covers every list in the block.

```rust
fn exclusion_list(st: &ChainState, blk: &BookBlock, pay: &Payloads) -> ExclusionList {
    let b = blk.header.book;
    let (e, s) = (blk.header.epoch, st.signer_of(blk));        // s from the seq_sig key
    let i = interval(e, b, blk.header.height);
    let mut entries = Vec::new();
    for (rec, r) in blk.packet_records().enumerate() {
        let sess = st.session(r.session);
        let reason = if sess.dead_before(b, blk.header.height, rec) {
            Some(SESSION_DEAD)                                  // after its first exclusion
        } else if sess.no_key(e, s) {
            Some(NO_KEY)
        } else {
            let p = pay.get(r.pkt_hash);                        // held before voting (07)
            let body = p.body_without_tags();
            let ok = [i, i - 1, i + 1].into_iter().filter(|j| (1..=N).contains(j))
                .any(|j| siphash24(st.k_com(sess, e, s, j), body) == p.tag_com());
            if ok { None } else { Some(BAD_COM) }
        };
        if let Some(reason) = reason {
            entries.push(ExclEntry { rec: rec as u32, session: r.session, pkt_seq: r.pkt_seq, reason });
        }
    }
    ExclusionList { book: b, height: blk.header.height, entries }
}
```

- **Who computes it:** the validator box of every committee member other than s, incrementally as
  payloads arrive. The leader, always a member (§4.3), puts its result in the chain block.
- **How votes cover it:** `excl_root` is in the `ChainHeader`, and every vote signs the header hash.
  Members recompute and notarize only on equality (§4.3 check 3).
- **Determinism (`INV-CHN-EXCL`):** the function reads only chain state, the book block and the
  payloads. It reads no clock, no local configuration and no arrival order.
- **A missing payload is never an exclusion.** Whether a node holds a payload is not a
  deterministic verdict. A voter that lacks a payload does not vote. `07-replication.md` specifies
  how it gets the bytes (from the data tier, or from the sequencer, which received them).
- **`SESSION_DEAD`:** once a packet of a session is excluded, every later packet of that session in
  the book group's order stream is excluded too. This makes the bust (§5.9) cover everything the
  session did after its first bad packet, without trusting the sequencer to stop in time.

### 5.8 TagFault and suspension

A member that finds a `BAD_COM` packet does not wait for the chain block. Its validator box sends
`TagFault { epoch, book, height, rec, session, pkt_seq, sig by NK }` to the sequencer's control
port. When the sequencer holds `TagFault`s for one session from `CHN_TAGFAULT_QUORUM` (2) distinct
operators, it suspends the session: a control op in the session's lane, logged in the order stream,
after which the lane rejects the session's packets with `SESSION_CLOSED`.

- **Latency (budget):** the check runs within ~50 µs of the payload's arrival, and one metro hop is
  ≤ 0.5 ms, so a bad session is suspended ≤ 1 ms after its first bad packet.
- **One byzantine member cannot suspend an honest session**, because the quorum is 2.
- **A byzantine sequencer can ignore `TagFault`s.** That changes nothing in the final state:
  `SESSION_DEAD` excludes every later packet, and the bust covers them. It only lets more fills go
  out that are busted later. §13 publishes the time from the second `TagFault` to the suspension per
  sequencer.

### 5.9 The bust, and who pays

When chain block C includes an exclusion list with entries for session σ, the following runs as
lane ops at the first boundary after C is final (deadline `act(C, b)`, §4.6), in this order:

1. **Cancel.** Every resting order of σ is canceled, whether its packet was excluded or not. σ is
   closed.
2. **Reverse.** Every fill in which one side is an order from an excluded packet of σ is reversed.
   Each party's allocation changes by the negative of that fill's settlement in base and quote, and
   both fees are refunded. This covers every fill of such an order from its entry to its cancel in
   step 1, including fills in book blocks after the excluded one.
3. **Pay.** σ's bond is seized. Each counterparty of a reversed fill f receives
   `min(CHN_BUST_COMP_BPS × notional(f), its pro-rata share of the bond)`. The rest goes to the
   insurance fund.
4. **Notify.** Every party of a reversed fill receives a `Bust` response record (0x87, 01 §14.10;
   layout in §17.2) on its sessions and a drop-copy record with the execution ID.

Each lane applies the reversals as one net op per (account, book), so a bust costs a lane one op
per affected account, not one per fill, and the item cap (§4.6) holds.

**A bust is not a finality exemption.** A fill is final when its block is final, ≤ 10 ms after the
order was sent (§4.8). Its fate is fixed at that moment: the exclusion list of the block that holds
the order's packet is final with it, and that block is the fill's own block or an earlier one. No
later event can bust a final fill whose packets passed `tag_com`. A bust only executes a verdict that
is already final, and only for fills against a packet that failed `tag_com`: a misbehaving client,
or the indistinguishable case below. **Timing (bound):** the bad packet's block h is final ≤ 8.11 ms after it
starts, so the bust ops apply and the `Bust` records leave ≤ 9.11 ms after h starts, ≤ 9.16 ms after
the bad packet was sent, and within the 10 ms. A bust that affects more than
`CHN_ITEM_OPS_PER_BLOCK` accounts on one lane finishes one block later per 16 accounts.

**Second-order effects stand.** A fill between two other parties that would have gone differently
without the excluded orders is not changed. This is the rule for a trade bust at a conventional
venue, and it is what keeps the engine from rewinding: matching replays exactly as it ran, so the
live book never diverges from the replay (`INV-DET`).

**Bust debt.** A reversal can make a counterparty's `available` negative, when the counterparty
already spent the proceeds. The lane keeps the negative value as a debt. While any balance of an
account in a book is negative, its lane accepts from it only cancels and orders that reduce the debt
(`RISK_CREDIT` otherwise). After `CHN_DEBT_GRACE_S` (3,600 s), the chain settles what is left: it
debits the account's other balances at the busted fill's price, and the insurance fund covers any
shortfall. Every reversal is a transfer between two allocations, so no asset is created or destroyed
(`INV-CHN-NOMINT`).

**Bond size.** `CHN_BOND_PER_MSGRATE` (0.01 USDC per message per second of rate limit) ties the
bond to how much a session can do before its suspension. A session allowed 10M messages per second
posts at least 100,000 USDC.

**The case nobody can tell apart.** A packet with a valid `tag_seq` and a bad `tag_com` comes from
the client or from the sequencer, and no proof says which. The client's bond pays in both cases.
A byzantine sequencer can therefore cost an honest client one bond per session, and it gains nothing
unless it also trades against the forged order. That is bounded by one bond per victim session, it
shows up in the per-sequencer exclusion rate (§13.4), and it is listed in §15.

### 5.10 TESLA disclosure and public verification

```
KeyDisclosure { session: SessionId, epoch: Epoch, seq_op: OpIdx, index: u32, value: [u8; 32] }
```

A disclosure is self-certifying: hashing `value` `index` times must give the on-chain anchor
`A(epoch, seq_op)`. It needs no signature and no consensus.

- **When:** `c(e, s, i)` may be disclosed once every book block of interval i + 1 or earlier is
  final, because blocks of interval i + 1 still accept `K_com(e, s, i)`. In practice that is when a
  block of interval i + 2 is final, about 2 s after interval i ends (budget).
- **Who:** the client SDK discloses the newest allowed index every `CHN_DISCLOSE_PERIOD_S` (10 s).
  Every committee member discloses, for every session that has not disclosed for 60 s, the newest
  allowed index, and at the end of the epoch `c(e, s, N)` for every session. One honest member is
  enough. Disclosures go to the disclosure stream of the public log (§11.4), not into chain blocks.
- **Cost:** about 100k sessions × 45 bytes per 60 s ≈ 75 KB/s (budget).
- **Disclosing is safe.** `c(e, s, i)` reveals keys for intervals ≤ i of one (e, s) chain, and every
  block that accepts those keys is already final. It reveals nothing about later intervals, other
  epochs or other sequencers.

**Verification by a third party:**

```rust
fn audit_block(chain: &ChainState, blk: &BookBlock, pay: &Payloads,
               disc: &Disclosures, cert_list: &ExclusionList) -> Result<(), WrongExclusion> {
    let (e, s) = (blk.header.epoch, chain.signer_of(blk));
    let i = interval(e, blk.header.book, blk.header.height);
    for (rec, r) in blk.packet_records().enumerate() {
        let sess = chain.session(r.session);
        let d = disc.newest(r.session, e, s).filter(|d| d.index >= (i + 1).min(N));
        let Some(d) = d else { continue };                       // not yet disclosed: skip
        assert!(hash_n(d.value, d.index) == sess.anchor(e, s));  // self-certifying
        let keys: Vec<_> = [i - 1, i, i + 1].into_iter().filter(|j| (1..=N).contains(j))
            .map(|j| kcom_from(hash_n(d.value, d.index - j))).collect();   // c(j) = H^(index−j)
        let mine = verdict(pay.get(r.pkt_hash), &keys, sess, blk, rec);
        if mine != cert_list.reason_of(rec) { return Err(WrongExclusion { .. }); }
    }
    Ok(())
}
```

A mismatch proves that at least 2 committee members signed a chain block with a wrong `excl_root`.
That is outside the fault model, so it should never happen. If it does, the mismatch is
`WrongExclusion` evidence (§8.2): the state machine re-runs the same check on the submitted packet,
key and anchor, and slashes every member that signed `Finalize` for that chain block.

**If the client never discloses**, nothing about validity changes. The committee already decided
every verdict when it voted, and the certificate is final. The members' disclosure duty makes the
keys public anyway. If every member also withholds, which takes all 4 members and so at least 3
honest operators breaking protocol, third parties cannot re-check `tag_com` for that session. They
can still replay everything else: order, matching, balances. The anchor stays on chain forever, so a
late disclosure is still verifiable.

## 6. Custody and the bridge

### 6.1 Choice: an Ethereum L1 contract

User funds sit in one contract on Ethereum mainnet. The contract releases funds only against
4-of-5 secp256k1 signatures from the operators' bridge keys.

- **Why L1 and not an L2:** an L2 adds its own sequencer, upgrade keys and proof system to the trust
  base, and an optimistic L2 adds 7 days to every exit to L1. Native USDC and the deepest liquidity
  are on L1.
- **Why secp256k1:** `ecrecover` is an EVM precompile at 3,000 gas per signature (vendor), so 4
  signatures cost about 12k gas. Ed25519 has no precompile on L1.
- **Why not a light client of VYRN on L1:** verifying VYRN's Ed25519 certificates in
  Solidity costs about 1M gas or more per signature (budget estimate). The validators are the
  same 5 operators either way, so a multisig of their bridge keys has the same trust assumption at
  a small fraction of the cost.
- **Immutable contract.** It has no proxy and no admin upgrade. A new contract is a new bridge that
  governance adds and users opt into. The contract is EVM-generic, so governance can add a second
  instance on an L2 later.

### 6.2 Contract interface

```solidity
function deposit(address token, uint256 amount, uint8 ownerKind, bytes32 owner) external;
    // emits Deposited(uint64 nonce, address token, uint256 amount, uint8 ownerKind,
    //                 bytes32 owner, address sender)
function proposePost(Post calldata p, bytes[] calldata bridgeSigs) external;   // ≥ 4 distinct BK
function veto(uint64 postNo) external;                                         // any one GK
function claim(uint64 postNo, Withdrawal calldata w, bytes32[] calldata proof) external;
function pause() external;                                                     // any one GK
function unpause(bytes[] calldata bridgeSigs) external;                        // 4 BK, then 24 h
function rotateSigners(SignerSet calldata s, bytes[] calldata bridgeSigs) external; // queued 72 h
function enterEscape() external;          // only if no post accepted for CHN_ESCAPE_S
function escapeClaim(BalanceLeaf calldata l, bytes calldata smtProof) external;
function refundDeposit(uint64 nonce) external;                                 // escape mode only

struct Post {
    uint64  postNo;  uint32 chainId;  bytes32 prevPost;
    bytes32 commit;               // hash of the StateCommit this post checkpoints (§9.5)
    bytes32 smtRoot;              // from that StateCommit
    uint64  depositNonce;         // highest deposit nonce credited in that state
    bytes32 wdRoot;               // keccak256 Merkle root over Withdrawal leaves
    uint32  wdCount;
    uint256[] wdTotals;           // per token, in asset order
}
struct Withdrawal { uint64 wdId; address token; uint256 amount; address recipient; }
```

The withdrawal tree in a post uses keccak256, because the contract must verify it cheaply. Every
other structure uses BLAKE3 (Request to 01, §18). Bridge signatures are EIP-712 signatures over
`Post`, with the same domain as transactions (§4.4).

### 6.3 Deposits and the confirmation policy

1. A user calls `deposit`. The contract assigns the next nonce and emits `Deposited`. The owner is
   an EVM address or an Ed25519 key. The account's `exit_address` defaults to `sender`.
2. Each operator runs its own L1 nodes (an execution client and a consensus client) on its commit
   boxes. Operators use different client implementations from each other.
3. **Only finalized L1 blocks count.** A validator reports an L1 event only once the block that
   contains it is at or below the L1 finalized checkpoint. That takes about 12.8 minutes (two L1
   epochs, vendor). Undoing a finalized checkpoint requires at least one third of L1 stake to be
   slashed. "Head" and "safe" blocks never count, and no count of confirmations replaces finality.
4. Each operator submits `L1Attest { l1_block: u64, l1_block_hash: [u8; 32], events: [L1Event] }`
   with the events of finalized L1 blocks in log order.
5. The state machine credits deposit nonce n once `CHN_ATTEST_QUORUM` (3) distinct operators have
   attested an identical `Deposited` event for n. It credits in nonce order only. The first deposit
   for an unknown owner creates the account.

Why 3 attestations and not 2: 2 already include one honest operator, which is enough for safety. The
third tolerates one honest operator whose L1 node has a bug. Liveness of deposits then needs 3 of 5
working L1 nodes. If L1 finality stalls, deposits wait. There is no fallback to unfinalized blocks.

### 6.4 Withdrawals

```
 user          VYRN                               L1 contract                      user
  │ Withdraw ──► end of chain block C:
  │               free → pending_withdraw (wdId)
  │             every CHN_POST_S (60 s), if any are pending:
  │               Post k = {StateCommit after the debits, wdRoot of pending ones}
  │               validators sign Post k with BK (4 of 5)
  │             relayer ─────────── proposePost(k) ──► accepted; challenge clock starts
  │                                                    CHN_CHALLENGE_S (3,600 s)
  │                                                    any GK may veto(k)
  │                                                    after the period: claimable
  │                                                    claim(k, w, proof) ◄─────────── │
```

| Step | Time (budget) |
|---|---|
| `Withdraw` included and applied | ≤ 2 ms + end of chain block |
| Included in the next post | ≤ 60 s |
| Post signed by 4 bridge keys and proposed on L1 | ≤ 1 min (one L1 slot is 12 s, vendor) |
| Challenge period | 1 h |
| Claim | one L1 transaction, paid by the user or a relayer |
| **Total** | **about 1 h 3 min** |

- A post always checkpoints the full state: its `commit` names a `StateCommit` whose SMT already
  reflects the debits of its withdrawals. That ordering is what makes the escape hatch (§6.6)
  double-spend free.
- If no withdrawal is pending, a post is still made every `CHN_CHECKPOINT_S` (3,600 s), so that
  the L1 contract always holds a balance root less than an hour old.
- `CancelWithdraw` works until the withdrawal is in a post that the validators signed.
- The contract limits the outflow per token to `CHN_BRIDGE_DAILY_CAP_BPS` (1,000 bps, 10%) of its
  balance per rolling 24 h. Claims above the cap wait. This bounds the loss if 4 bridge keys are
  stolen and every guardian fails to react.
- An L1 post costs about 150k gas (budget estimate). At one post per minute that is about 216M gas
  per day, a few ETH at typical gas prices. `CHN_POST_S` is a governance parameter.

### 6.5 Challenge and veto

Any one guardian key can veto a post during its challenge period. A veto delays a post and never
destroys it:

- The vetoed post's withdrawals stay pending in state.
- The same post can be proposed again with 5-of-5 bridge signatures at once, or with 4-of-5 after
  `CHN_VETO_OVERRIDE_S` (72 h). A post accepted by override cannot be vetoed again.
- Later posts are not blocked by a vetoed one. Each post's claims are independent.

Who vetoes: each operator's guardian process recomputes every proposed post from its own validator's
state. It vetoes when the post differs from its own computation. A post that 4 bridge keys signed but
that differs from the chain's post with the same number is `BadPost` evidence (§8.2).

### 6.6 Pause and escape

| Event | L1 contract | VYRN |
|---|---|---|
| `pause()` by any one guardian | Rejects deposits, proposals and claims | Trading continues. `Withdraw` is accepted and stays pending. Deposits finalized before the pause are still credited. Validators stop signing posts. |
| `unpause` by 4 bridge keys | Effective 24 h after the call | Posts resume; pending withdrawals go into the next post |
| No post accepted for `CHN_ESCAPE_S` (14 days) | Anyone may call `enterEscape()`; escape is permanent | The bridge is dead. Governance must deploy a new one. |

**Escape mode.** The contract takes the last accepted post's `smtRoot` as final. A user calls
`escapeClaim` with its `BalanceLeaf` (§9.3) and an SMT proof. The contract pays
`free + alloc_sum + transit + pending_unposted` of that leaf to the leaf's `exit_address`.
Withdrawals in accepted posts stay claimable as usual, and the post's state already excludes them,
so nothing is paid twice. Deposits with a nonce above the post's `depositNonce` are refunded to
their sender with `refundDeposit`. Escape proofs use BLAKE3 in Solidity, about 1M gas per claim
(budget estimate, §19). Escape is a last resort, and its cost is acceptable for that.

Why one guardian can pause: a pause stops theft at the cost of liveness, and liveness has a 14-day
backstop. A byzantine guardian that pauses repeatedly is removed by signer rotation.

### 6.7 Bridge key rotation

1. Governance approves the new signer set (`SetParam` on the signer table, loosening, 72 h).
2. At activation, 4 of the 5 current bridge keys sign `rotateSigners(new set, rotation_no)`.
3. The contract queues the rotation for `CHN_BRIDGE_ROTATE_S` (72 h). Any guardian can veto it in
   that time, and a veto can be overridden with 5-of-5.
4. After activation, posts need signatures from the new set. Posts accepted earlier stay claimable.

The L1 delay exists on its own because the contract cannot see VYRN's governance. If 4 bridge
keys are stolen, the thief can try to rotate to its own keys, and the 72 h window lets guardians
veto and pause. Guardian keys rotate by the same flow.

**Owner.** The signer table (rotation number → `SignerSet`) is a key table, owned by `vyrn-epoch`
with the other per-epoch keys (08 §9.5). A set that governance approves activates at the first epoch
boundary after approval, and every activated set stays readable by rotation number, because posts
accepted under it stay claimable (step 4). `vyrn-chain` reads it through `Epochs::bridge_signers`.

### 6.8 What stays classical: the bridge and EVM wallets

01 §14.20 makes every VYRN-internal signature hybrid. Two keys cannot follow, because the other
side checks them.

**Exposure.**

- **The bridge.** The contract verifies `BK` and `GK` with `ecrecover` (§6.1). `ecrecover` is
  secp256k1 only, and verifying ML-DSA in Solidity has no precompile and no known affordable cost.
  [Certain for `ecrecover`; Guessing on the gas of a Solidity ML-DSA verifier, which this chapter
  did not measure] Every bridge or guardian signature on L1 reveals its public key. An attacker with
  a cryptographically relevant quantum computer recovers the private keys from it. With all 5
  `BK`s it signs a false post, overrides any veto with 5-of-5 (§6.5) and rotates the signer set
  (§6.7). With the `GK`s it vetoes or pauses honest posts. The 10% daily cap (§6.4) still holds
  inside the contract, so the loss is ≤ 10% of the balance per day while the attack lasts; the
  escape hatch (§6.6) does not help, because a forged post is accepted. [Likely]
- **EVM wallet sessions.** An account with a `Secp256k1` `OwnerKey` is as safe as that key. Its
  public key is on Ethereum once it has sent an L1 transaction. A quantum attacker can then open
  sessions and `Withdraw` as the owner. `exit_address` (§6.2) bounds where the funds go only if the
  attacker cannot also change it, and `SetExitAddress` is signed by the same owner key.
- **Ed25519 `OwnerKey`s and session keys** have the same exposure until the owner moves to a
  `Hybrid` key. Session `sign_pub` keys live ≤ 3 epochs, which limits but does not remove it.
- **What stays safe.** Votes, `seq_sig`, every certificate, the chain's state and the light-client
  history (§10) are post-quantum from `E_pq`, with `pq_anchor` (01 §14.20 SG6) fixing the switch.
  A quantum attacker cannot forge VYRN's history or its finality; it can only steal through the
  classical keys above.

**Migration hook.**

1. **Hybrid owner keys.** `OwnerKey::Hybrid` and an item `SetOwnerKey { new: OwnerKey }`, signed by
   the current owner key, are available from `E_pq`. Wallets that support ML-DSA move first; an
   EVM wallet keeps its `Secp256k1` key until it can.
2. **Classical cutoff.** Governance sets `CHN_PQ_OWNER_CUTOFF` (an epoch, unset by default) with the
   72 h timelock. At that epoch every account whose `OwnerKey` is still classical gets a permanent
   flag `exit_frozen` and keeps the `exit_address` in force at the cutoff. The flag is account
   state and survives every later `SetOwnerKey`: a frozen account never accepts `SetExitAddress`,
   and all its withdrawals go to the frozen address, whoever holds the owner key. A classical key
   may still sign `SetOwnerKey` (so the owner can trade again under a hybrid key), `Withdraw` and
   `CancelWithdraw`. A quantum attacker who recovers the classical key and installs its own hybrid
   key can therefore trade the account but can send funds only where the owner already said. An
   owner who loses access to the frozen address recovers through governance, out of band. Accounts
   that move to a hybrid key before the cutoff are not frozen.
3. **A second bridge.** The contract is immutable (§6.1), so the post-quantum bridge is a new
   contract that governance adds and users opt into. Its signature check is a pluggable verifier
   address fixed at deployment: a precompile when Ethereum offers one, or a proof that VYRN's
   hybrid `CommitCert` verifies. Bridge keys `BK′` are then hybrid. Its design is out of scope.
   Governance deploys it when Ethereum ships a post-quantum signature precompile (01 §14.20 PQ-5);
   a Solidity ML-DSA verifier or a ZK proof of the `CommitCert` is not built before that.
4. **`PqAlarm`.** A governance action (tightening, so it acts at once, §2.10). The immutable
   contract has no deposit-only switch, and `pause()` (§6.6) also blocks proposals and claims, so
   `PqAlarm` does not pause it. Instead: the validators sign only posts whose withdrawals all go to
   recorded exit addresses (frozen ones included); the SDK, wallet integrations and the public RPC
   refuse to build deposits to the old bridge and point to the new one; and deposits that still
   arrive are credited as usual, so no funds are stranded. Guardians keep `pause()` for an attack in
   progress, as today. The old bridge then holds a shrinking balance that its 10% cap protects.
   [Likely: deposits stop by tooling, not by the contract] **Trigger (PQ-5):** governance raises
   `PqAlarm` on a published estimate that a cryptographically relevant quantum computer exists or
   is within the timelock horizon, or at once on any public demonstration that a secp256k1 or
   Ed25519 private key was computed from its public key. From `PqAlarm`, `BadPost` evidence is
   verified and recorded but moves no bond (§8.1 item 2a), because a quantum attacker can forge
   the secp256k1 signature it rests on.
5. **Disclosure.** The service contract states: "Funds in the L1 bridge and accounts with classical
   owner keys are not protected against a quantum attacker. VYRN's ordering, finality and history
   are." 01 §14.20 PQ-5 (decided) fixes when step 3 deploys and when step 4 is raised;
   `CHN_PQ_OWNER_CUTOFF` stays open (§19 question 12).

## 7. Forced inclusion

### 7.1 Path

A client that the sequencer ignores sends its packet as a `ForcedPacket` item on the transaction
path (§4.4) to the validator boxes of all 4 committee members other than s. Each relays it to the
live sequencer as a **hint**. The next leader includes the item in its chain block. An honest
sequencer applies the forced packet at the earlier of two points:

- **the hint:** the control core verifies the session's Ed25519 signature (~40 µs, off the 1 µs
  path) and injects the packet into its lane as a packet, logged as an `ItemRecord`;
- **the boundary:** the first block boundary after the chain block that includes it is notarized
  (01 §14.9, §4.6).

Its deadline is `act(C, b)`. A sequencer that misses it is censoring: voters fail check 4, treat
it as silent, and submit `Censorship` evidence (§8.2).

### 7.2 Format

```
ForcedPacket {                         // TxEnvelope kind 0x10, signer = Session(σ)
    packet: [u8; ≤ MAX_REQ_PAYLOAD],   // the request packet of 01 §6.1; tags may be zero
}
// envelope.nonce = packet.pkt_seq; envelope.sig = Ed25519 by σ.sign_pub over
//   derive_key("vyrn      v1 tx", envelope without sig)
```

A forced packet is authenticated by the session's Ed25519 signature, not by its tags. Why: with
tags alone, one byzantine committee member (which knows `K_com`) could forge a forced packet, and
only the sequencer could check `tag_seq`, so a byzantine sequencer could reject an honest forced
packet by claiming a bad `tag_seq`. A signature is checkable by everyone and settles both cases.
The forced path is low-rate, so the signature cost is small: 50k forced packets per second cost
about 1 core per validator (budget).

### 7.3 Positioning and deduplication

- The packet applies at the hint or at the first boundary after C is notarized, and never after
  `act(C, b)` (§4.6, §7.1). Its position is logged, so replay applies it at the same op. The
  signature makes it valid in any position, and the members hold its bytes from the client, so it
  needs neither a final schedule nor the data tier.
- If the lane has already applied `(σ, pkt_seq)` on the fast path, the forced copy is a no-op and the
  lane records it as a duplicate.
- If `pkt_seq` is beyond a gap, the lane applies it and marks the gap entry as filled. The fast path
  rules for gaps are in `04-protocol.md`, which must accept a forced packet out of order (§16).
- Responses go to the session as normal response packets, with `echo_pkt = pkt_seq`.
- A sequencer that has not applied a forced packet by `act(C, b)` produces a book block that fails
  voter check 4 (§4.3). It gets no votes, the voters treat it as silent, and failover replaces it.
  The new sequencer applies the packet in its first block.

### 7.4 The censorship bound

With f = 1 the fault is either the sequencer or someone else, never both (bounds are budgets, hop
δ = 0.8 ms, a view ≤ 1.6 ms):

| Case | Path | Bound |
|---|---|---|
| Honest sequencer, one other fault | client → members δ, hint → sequencer δ, verify 0.04; then the block's finality ≤ 8.11 (§4.8) | **final ≤ 9.75 ms after send** |
| Honest sequencer, every hint lost (outside the model: 4 members relay it) | to leaders δ, proposal ≤ 1.6, notarized +1.65, boundary ≤ 1, finality 5.31 | final ≤ 10.4 ms |
| Censoring sequencer (the fault) | included ≤ 2.4 ms (every leader is honest); deadline `act(C, b)` ≤ 10.4 ms; then failover and finality | **final ≤ ~10.4 + `FAILOVER_TARGET_MS` + `FINALITY_MAX_MS` ≈ 41 ms** |

So under an honest sequencer a forced packet is final ≤ 10 ms after it is sent, like any order
(01 §14.9): the hint path is 9.75 ms, and only a loss of every hint, which is outside the model,
leaves the slower boundary path. A censoring sequencer can keep a packet out of the log for ≤ 2.4 ms, which is the bound
in `DESIGN.md` §7. It can delay execution only by getting itself replaced, and the packet is final
within `FAILOVER_TARGET_MS` + `FINALITY_MAX_MS` of the deadline (01 §14.0 fact 3).

### 7.5 Limits

`CHN_FORCED_RATE` (100 packets per second per session) and `CHN_FEE_FORCED` (0.01 USDC per packet)
make the forced path useless for normal trading and cheap as an escape. A validator checks the
session, the rate and the fee before it verifies the signature, so junk costs it only those cheap
checks.

## 8. Slashing and evidence

### 8.1 Processing

Anyone submits an `Evidence` item. Its handling is automatic:

1. The state machine verifies the evidence against chain state: Ed25519 (hybrid from `E_pq`, 01 §14.20) verification for votes and
   `seq_sig`s, `ecrecover` for bridge signatures, recomputation for `WrongExclusion` and `BadPost`.
   Each check is deterministic.
2. Evidence older than `CHN_EVIDENCE_EPOCHS` (42 epochs, 14 days) is rejected. Duplicate evidence
   (the same fault by the same operator) is a no-op.
2a. **Classical evidence after the switch (01 §14.20 SG7).** Evidence is *classical* when **any**
   signature it relies on is scheme 0: an offending signature in the table below, or a
   certificate or record that the check uses (a `NodeCert`, a handoff or finalization
   certificate). An authentic hybrid signature elsewhere in the item does not change that: a
   genuine hybrid-signed `NodeCert` that certifies a scheme-0 vote key leaves a forged scheme-0
   vote forgeable. From the first chain block of `E_pq`, classical evidence slashes or jails only
   if it, or `EvidenceCommit { hash }` of its encoding, is in a chain block final before `E_pq`
   began. Otherwise it is still verified, each signature under the rules of its own scheme (a
   hybrid `NodeCert` signature under 01 §14.20 A, a scheme-0 vote under 11 §2.5), and, if valid,
   recorded; it changes no bond and no jail. `BadPost`'s secp256k1 signature is not a `SigScheme`; `PqAlarm` covers it (below).

   | Evidence | Offending signatures (the misconduct itself) | Signatures it relies on besides |
   |---|---|---|
   | `SeqEquivocation` | `a.seq_sig`, `b.seq_sig` | — |
   | `DoubleVote` | `a.sig`, `b.sig` | — |
   | `FenceViolation` | `h.seq_sig` | the `HandoffCert` |
   | `HandoffWithheld` | the four `HandoffTimeout` signatures | — |
   | `CrossHomeVote` | `v.sig` | `cert.sig` (the `NodeCert`) |
   | `DoubleCommit` | `a.sig`, `b.sig` | — |
   | `Censorship` | the `seq_sig` of every book header in `(lastb(C), h]` | the finalization certificate of `C` |
   | `WrongExclusion` | the finalization certificate of the block | — (the disclosure is a hash preimage) |
   | `BadPost` | `sig` (secp256k1, outside SG7; moves no bond from `PqAlarm`, §6.8) | — |

   Why: after the switch a quantum
   attacker can forge scheme-0 signatures for the old epochs at will, and two forged `DoubleVote`s
   would jail two operators and stop finality (4 of 5 needed) without touching a hybrid key. The
   cost: a fault committed in the last moments of `E_pq − 1` and not committed on chain before the
   switch goes unpunished on chain; honest nodes submit `EvidenceCommit` as soon as they detect a
   conflict, within milliseconds. Replay of history keeps classical verification. `BadPost`
   evidence rests on secp256k1 bridge signatures and stays classical after `E_pq`; it slashes
   until `PqAlarm` is raised and moves no bond from then on (PQ-5, §6.8).
3. The slash applies at the end of the including chain block: bond balance moves to the insurance
   fund, and `CHN_REPORTER_SHARE` (5%) goes to the submitting account. A jail takes effect at the
   next boundary (§4.6), and the operator leaves the leader schedule and the sequencer schedule.

### 8.2 Evidence formats

```
Evidence =
  | SeqEquivocation { a: BlockHeader, b: BlockHeader }
        // same book and height, different hashes, both seq_sig valid under one SK. Under
        // scheme 1 "different" means different bytes 0..126: hedged signing gives two valid
        // signatures of one header, which is not evidence (01 §14.20 A)
  | DoubleVote { a: VoteMsg + sig, b: VoteMsg + sig }
        // same operator and (epoch, view); Notarize/Notarize or Finalize/Finalize with
        // different blocks, or Finalize/Nullify. Keys may be any two of the operator's VKs.
  | FenceViolation { handoff: HandoffRecord + cert, h: BlockHeader }
        // h.epoch = handoff.epoch and h.height > handoff.last_height, seq_sig valid
  | HandoffWithheld { epoch: Epoch, attests: [HandoffTimeout + sig; 4] }          // §8.3
  | CrossHomeVote { v: VoteMsg + sig, cert: NodeCert }
        // valid under a VK of a home that is not eligible for v.epoch
  | DoubleCommit { a: CommitVote, b: CommitVote }
        // same operator, same chain_id and second, different StateCommit hashes
  | BadPost { p: Post, sig: [u8; 65] }
        // valid BK signature on a Post whose content differs from the chain's post p.postNo
  | Censorship { block: ChainHeader + finalization cert, item: u16 + proof,
                 h: BlockHeader, lane_records: [ItemRecord] + proof }
        // a lane item of a final chain block C is absent from the book blocks (lastb(C), h],
        // h = act(C, b) after carries, all signed by one SK; proofs cover each block's
        // item section of that lane. Censoring is not a crash, so it jails.
  | WrongExclusion { block: ChainHeader + finalization cert, list: ExclusionList + proof,
                     rec: u32, packet: [u8; ≤ 192], disclosure: KeyDisclosure }
        // the disclosed key gives a verdict that differs from the certified list
```

### 8.3 The withheld handoff

At the epoch's end time T, the sequencer must stop and emit its `HandoffRecord` (`08-epochs.md`).
If no `HandoffRecord` has reached a committee member by `T + CHN_HANDOFF_DEADLINE_MS` (10 ms), the
member signs `HandoffTimeout { epoch, last_final_height }`. Four such signatures are a quorum fact
that the handoff was withheld. The committee then builds and certifies the `HandoffRecord` from the
last finalized book block itself, so the next home starts without the sequencer. Absence cannot be
proved by one signature, so this is the one fault proved by quorum attestation. It is slashed
lightly, because an honest crash at T produces the same attestations.

### 8.4 Amounts

| Fault | Slash (budget, governance parameter) | Jail |
|---|---|---|
| `SeqEquivocation` | 100% of the sequencer bond + 50% of the operator bond | yes |
| `FenceViolation` | 100% of the sequencer bond | yes |
| `DoubleVote` | 50% of the operator bond | yes |
| `WrongExclusion` | 50% of the operator bond of each operator whose `Finalize` is in the certificate, except the sequencing operator | yes |
| `BadPost` | 100% of the operator bond | yes |
| `DoubleCommit` | 25% of the operator bond | yes |
| `Censorship` | 10% of the sequencer bond | yes |
| `HandoffWithheld` | 2% of the sequencer bond | no |
| `CrossHomeVote` | 1% of the operator bond | no |

Faults that can fork the chain or steal funds take most of a bond and jail the operator. Faults that
an honest crash can cause take a small amount and do not jail. `SeqEquivocation` takes both bonds
because one equivocation can make different clients see different fills.

## 9. State commitments

### 9.1 Summary

| Commitment | Cadence | Structure | Lets you | Cost (budget) |
|---|---|---|---|---|
| Log hash chain | every chain block | BLAKE3 chain over headers and roots | check that two copies of the log are identical | ~5 cores per validator box, mostly per-packet hashes |
| Balance SMT | every 1 s | sparse Merkle tree, BLAKE3, depth 256 | prove one balance to a light client | ~2 cores on the commit box |
| Order LtHash | every 1 s | lattice hash of the resting-order set | check a snapshot of the book; detect divergence | ~6 cores on the commit box |
| `StateCommit` + `CommitCert` | every 1 s | one record, 4 Ed25519 signatures | anchor all three for light clients and L1 | 1 signature per second per operator |

### 9.2 The log hash chain

```
log_hash(H) = BLAKE3(derive_key("vyrn      v1 log",
                log_hash(H − 1) ‖ books_root(H) ‖ items_root(H) ‖ excl_root(H)))
log_hash(0) = genesis_hash
```

`books_root` covers every `BlockHeader`, and each header covers its `order_root` and `data_root`
(01 §6.6). So `log_hash(H)` commits to every order-stream record, every payload, every item and every
exclusion up to chain height H. The `HandoffRecord.log_hash` is the `log_hash` of the last chain
block of the epoch.

| Work per validator box at peak | Volume (budget) | Cores (budget) |
|---|---|---|
| `pkt_hash` of every payload, 16-way SIMD BLAKE3 | 145.5M packets/s (`WL-REF`), ≤ 176 B each | ~3 |
| `data_root` Merkle over packet hashes | ~145k leaves per book block | ~1 |
| `order_root` over the encoded order stream | ≤ 25 Gbps ≈ 3.1 GB/s | ~1 |
| **Total** | | **~5** (`DESIGN.md` §7 has ~4 at 100M packets/s) |

### 9.3 The balance SMT

A binary sparse Merkle tree of depth 256. A key is a BLAKE3 hash, so leaves spread evenly.

| Leaf | Key | Value |
|---|---|---|
| `AccountLeaf` | `BLAKE3(0x01 ‖ le(account))` | owner kind and bytes, nonce, `exit_address` |
| `BalanceLeaf` | `BLAKE3(0x02 ‖ le(account) ‖ le(asset))` | `free`, `alloc_sum`, `transit`, `pending_unposted`, `pending_posted` (u128 each) |
| `AllocLeaf` | `BLAKE3(0x03 ‖ le(account) ‖ le(book) ‖ le(asset))` | `available` (i128, negative for bust debt), `reserved` (u128) |
| `SessionLeaf` | `BLAKE3(0x04 ‖ le(session))` | account, status, bond, epochs, `BLAKE3(anchors)` |
| `OperatorLeaf` | `BLAKE3(0x05 ‖ [op])` | bonds, jail flag, `NodeCert` hashes |

```
leaf_hash = BLAKE3(derive_key("vyrn      v1 smt leaf", key ‖ encode(value)))
node_hash = BLAKE3(derive_key("vyrn      v1 smt node", left ‖ right))
E[0] = [0; 32];  E[d + 1] = node_hash(E[d], E[d])        // the empty subtree of height d
proof = { bitmap: [u8; 32], siblings: [Hash] }           // bit d set ⇔ sibling at depth d not empty
```

With 100M leaves a proof has about 27 non-empty siblings, about 900 bytes (budget).

**Which state a commit covers.** Commit k covers the state at the end of chain block H = k ×
`CHN_COMMIT_BLOCKS` (1,000). Book-level values are those after the last book block included at or
before H, with every item applied by then. That is a pure function of the finalized chain prefix.

**Net diff.** The replay engine on the validator box marks every allocation it changes as dirty. At
commit k it sends the dirty leaves to the commit box and clears the marks. So the work per second
is the number of distinct changed leaves, not the number of fills. An account that trades a
million times in a second costs 2 leaf updates. Budget: 1M distinct changed leaves per second, about
20M node hashes, about 2 cores.

### 9.4 The order LtHash

```
elem(o)  = encode { book: u16, lane: u8, handle: u32, account: u32, side: u8,
                    tick: u32, open_qty: u32, rx_ts: u64 }                       // 28 bytes
v(o)     = BLAKE3_XOF(derive_key("vyrn      v1 lthash", elem(o)))[0..2048] as [u16; 1024] (LE)
L(S)     = Σ_{o ∈ S} v(o)   componentwise mod 2^16                               // S = resting set
L_k      = L_{k−1} + Σ_{o ∈ S_k \ S_{k−1}} v(o) − Σ_{o ∈ S_{k−1} \ S_k} v(o)
digest_k = BLAKE3(derive_key("vyrn      v1 lthash digest", L_k as bytes))
```

- An order whose `open_qty` changes is a different element: the commit removes the old element
  and adds the new one.
- **Orders that live and die within one second never touch `L`.** Each resting order carries a
  `committed` flag and its committed quantity. At commit k the lane walks only the orders it touched
  since commit k − 1: new and still resting → add; committed and now gone → remove; committed and
  changed → remove old, add new; new and already gone → nothing.
- Addition commutes, so each lane's diff is summed separately and the commit box adds the 50 lane
  sums. The work parallelizes across any number of cores.
- **Cost (budget):** one `v(o)` is a 2 KB XOF output, about 0.4 µs; the add is about 30 ns.
  Assume a net diff of 10M elements per second at peak, about 1% of joins surviving a second
  boundary, counted twice for add and remove. That is about 4 core-seconds per second, so the
  budget is 6 cores. Benchmark B-CHN-2 measures the real net-diff rate and the per-element cost.
- **Security:** 1024 × u16 is the parameter set that Solana adopted for its accounts lattice hash.
  Its collision resistance rests on the hardness of a lattice problem (SIS). We take that as a
  literature claim, not as our result.
- **Limits:** an LtHash proves no single order. It proves that a whole snapshot of the book is the
  one the validators hold, and it detects any divergence between validators within one second. To
  check one order, replay the public log.
- The full 2 KB vector `L_k` is published in the commitment stream (§11.4), so a node that syncs can
  continue the sum without rebuilding it.

### 9.5 StateCommit and its signatures

```
StateCommit {
    ctx: "vyrn      v1 commit", chain_id: u32, epoch: Epoch,
    height: Height,              // chain height H = second × CHN_COMMIT_BLOCKS
    second: u64,
    log_hash: Hash, smt_root: Hash, orders_lthash: Hash, orders_count: u64,
    books: [(BookId, Height)],   // the last book height of each book covered
    params_hash: Hash,           // hash of the ParamSet in force
    keys_hash: Hash,             // hash of EpochKeys(epoch), §10.2
    prev: Hash,                  // hash of StateCommit for second − 1
}
CommitVote { commit: Hash, op: OpIdx, sig: Ed25519 by VK(op, home(epoch))
             over derive_key("vyrn      v1 commit", encode(StateCommit)) }
CommitCert { commit: StateCommit, sigs: [(OpIdx, [u8; 64]); ≥ 4] }
```

- Every operator's commit box computes the `StateCommit` from its own validator box's replay. The
  validator box signs it with the vote key, so `INV-CHN-SPLIT` holds: the Vx operators' commits come
  from the Vx replay.
- Commit votes are gossiped to the committee. The next leader that holds 4 matching votes includes
  the `CommitCert` as an item (0x24). Budget: the `CommitCert` is on chain within
  `CHN_COMMIT_LAG_MS` (500 ms) after H.
- **Commits are decoupled from blocks.** No vote on a chain block waits for a commit, so a slow
  commit box never stalls consensus or trading.
- Two commit votes by one operator for one second with different hashes are `DoubleCommit` (§8).
- If the commit votes for a second do not reach 4 matching values within 10 s, at least one
  validator computes different state: a determinism bug. Every operator's node raises its highest
  alert, and `11-build.md` replays the second in `vyrn-sim` against the Vx oracle. The chain keeps
  finalizing order, because order and state are separate.

### 9.6 The commit box

| Work | Cores (budget) |
|---|---|
| SMT updates | 2 |
| LtHash | 6 |
| L1 execution client and consensus client | 8, plus 4 TB NVMe (vendor guidance for L1 clients) |
| Archive writer, snapshots | 4 |
| Public RPC and light-client proofs | 4 |
| **Total** | **~24**, so any 32-core COTS server |

## 10. Light clients

### 10.1 What a light client trusts

A light client trusts `genesis_hash` and, after a long absence, one recent checkpoint (§10.5). It
trusts no RPC server. Every RPC answer comes with a proof.

### 10.2 The validator-set history

```
EpochKeys(e) = { epoch: e, home: home(e), vote_keys: [[u8; 32]; 5],   // VK(i, home(e))
                 seq_keys: [[u8; 32]; 5],                              // SK(i, home(e))
                 jailed: u8 bitmap, seq_op: OpIdx }
keys_hash(e) = BLAKE3(derive_key("vyrn      v1 epochkeys", encode(EpochKeys(e))))
```

The `HandoffRecord` of epoch e carries `next_keys = keys_hash(e + 1)` (Request to 01, §18), and the
committee of e certifies it. So the handoff certificates form a chain from genesis:

```rust
fn follow_keys(genesis: &GenesisRecord, rpc: &impl Rpc, target: Epoch) -> EpochKeys {
    let mut keys = genesis.epoch_keys(0);
    for e in 0..target {
        let (rec, cert) = rpc.handoff(e);                 // HandoffRecord(e) + 4 signatures
        assert!(rec.epoch == e && cert.verify(&keys.vote_keys, Q_CHAIN));
        let next = rpc.epoch_keys(e + 1);
        assert!(keys_hash(&next) == rec.next_keys);
        keys = next;
    }
    keys
}
```

That is 3 handoffs per day, about 1,100 per year, each 4 Ed25519 verifications: well under a second
of CPU for a year of history (budget). A failover inside an epoch changes the sequencer, not the
vote keys, and `EpochKeys` lists the seq keys of all 5 operators, so failovers need no extra record.

### 10.3 Verifying a block or a transaction

- **A chain block:** the `ChainHeader` and its finalization certificate: 4 `Finalize` votes for
  `(epoch, view, block)` under `EpochKeys(epoch).vote_keys`.
- **A transaction receipt:** `Receipt { item_hash, height, index, result: u16, proof }`, where
  `proof` is the Merkle path from the item to `items_root`. The result code says what the item did
  at the end of its chain block; a lane result comes in a second receipt for the book block in which
  it applied.

### 10.4 Verifying a balance

```rust
fn verify_balance(keys: &EpochKeys, cc: &CommitCert, leaf: &BalanceLeaf, p: &SmtProof) -> bool {
    cc.commit.epoch == keys.epoch
        && cc.commit.keys_hash == keys_hash(keys)
        && cc.verify(&keys.vote_keys, Q_CHAIN)                       // 4 distinct operators
        && smt_verify(cc.commit.smt_root, leaf.key(), leaf.encode(), p)
}
```

The balance is at most 1 s plus `CHN_COMMIT_LAG_MS` old. A light client that needs the balance at
an exact block replays the public log from the nearest commit.

### 10.5 Weak subjectivity

Once an operator's bond has unbonded, its old keys cost it nothing, and a set of old keys could sign
a fake history (a long-range attack). So a light client that has been offline for more than
`CHN_WS_EPOCHS` (42 epochs, 14 days, shorter than the 21-day unbonding) must re-anchor from a recent
checkpoint before it trusts a new history. The natural checkpoint is the L1 contract: its latest
accepted post names a `StateCommit` hash, and reading it needs only an L1 light client.

## 11. Data availability and sync

### 11.1 What every validator stores

| Data | Rate at peak (budget) | Average at 10% load |
|---|---|---|
| Payloads (data) | ~30 GB/s (242 Gbps, 02 §5.2) | ~3.0 GB/s |
| Order stream | ~3.1 GB/s | ~0.31 GB/s |
| Chain blocks, certificates, items, exclusion lists | < 10 MB/s | < 1 MB/s |
| Commitment stream, disclosures | < 1 MB/s | < 1 MB/s |
| **Total** | **~33 GB/s** | **~3.3 GB/s ≈ 285 TB/day** |

A validator box votes only when it holds every payload a block references (`07-replication.md`). So
when a block is final, at least 4 operators held all of its data, and at least 3 of them are honest.

### 11.2 Retention

- Every node keeps at least 24 h of the full log hot on NVMe.
- Every operator keeps `CHN_HOT_DAYS` (7 days) hot in at least 2 of its 3 homes. At the average load
  that is about 2.0 PB per copy, about 65 drives of 30.72 TB (budget). Two homes per operator survive
  the loss of one home.
- Follower nodes receive the finalized log over the WAN (`08-epochs.md`), so all 15 nodes have it.

### 11.3 Archive

After 7 days the log moves to archive storage: HDD object storage in colo, or an archive storage
class in a cloud. Payloads are compressed with zstd; benchmark B-CHN-6 measures the ratio. Each
archived segment is named by its chain-height range, and its content is covered by `log_hash`, so
any copy can be checked against the chain. At least 2 operators, chosen by governance, each keep a
full archive for `CHN_ARCHIVE_YEARS` (7).

### 11.4 The public log

Anyone can replay the chain. The operators publish these streams:

| Stream | Content |
|---|---|
| `blocks` | chain blocks with headers, finalization certificates, items, exclusion lists |
| `order` | the order stream of every book block |
| `data` | every payload |
| `commits` | every `StateCommit`, `CommitCert` and full `L_k` vector |
| `disclosures` | every `KeyDisclosure` |
| `snapshots` | every snapshot (§11.5) |

They are served from each operator's archive with requester-pays transfer, and as a live finalized
feed about 1 s behind the head from the commit boxes. `vyrn-validator --role=replay` starts from any
snapshot and reproduces every state byte, every fill and every `StateCommit`.

### 11.5 Sync

- **Snapshots:** every `CHN_SNAPSHOT_S` (3,600 s) at a commit point, and at every epoch boundary.
  A snapshot is the canonical serialization of chain state and of every book's engine state (lanes,
  orders, allocations, BBO). Budget: ≤ 40 GB, about 4 s at 100 Gbps.
- **Checking a snapshot:** the node recomputes the SMT root and the LtHash from the snapshot and
  compares them with the `CommitCert` of that second. A snapshot from any source is then as good as
  one from the node's own operator.
- **Catching up:** the node replays the finalized log from the snapshot height. Replay must run at
  least `CHN_REPLAY_SPEEDUP` (2×) the peak live rate (budget), so a 1 h snapshot gap closes within
  1 h even at sustained peak. At the average load it closes in minutes.
- **Recovering after a crash:** a node whose gap is inside its local hot log replays from its own
  write-ahead state. Otherwise it takes a snapshot.
- **Where from:** first its own operator's nodes in the other homes, then any operator's archive.
- **A new validator for a home** syncs in the home where it will be active, then follows the live
  log. It must be in sync before its operator's first active epoch there (§2.9).

## 12. Economics

### 12.1 Fees per message class

The scarce resource is the BBO core: `CROSS_CAP` is 10M crosses per second, and every improve or
depletion takes `BBO_IMPROVE_NS` of it. Joins and cancels cost only lane time, which scales with the
number of lanes. So fees follow the BBO core, not the message count (`DESIGN.md` §3).

| Class | Resource it uses | Default fee (budget, governance parameter) |
|---|---|---|
| Cross (taker fill) | BBO core, `BBO_CROSS_NS` | `CHN_FEE_TAKER_BPS` = 2.0 bps of notional |
| Maker fill | none beyond the cross | `CHN_FEE_MAKER_BPS` = 0 |
| Improve | BBO core, `BBO_IMPROVE_NS` | `CHN_FEE_IMPROVE` = 10 µUSDC per message |
| Join | lane, `LANE_NS_PER_MSG` | `CHN_FEE_MSG` = 0.1 µUSDC per message |
| Cancel, Reduce, CancelAll | lane | `CHN_FEE_MSG` per message |
| Replace | lane, plus the BBO core if it improves or crosses | by the class of the new order |
| Heartbeat, ResendReq | lane | 0 within the session rate |
| Message in a busted packet | — | refunded (§5.9) |
| Transaction item | validators | `CHN_FEE_TX` = 0.01 USDC |
| Forced packet | validators | `CHN_FEE_FORCED` = 0.01 USDC |
| Session open | validators, lane slot | `CHN_FEE_SESSION` = 1 USDC, plus the bond |

- The lane classifies every order against its snapshot (01 §1), and replay reproduces that
  classification, so the fee class of every message is deterministic.
- Fees are charged in the book's quote asset, from the account's allocation in that book. Fill fees
  are part of the reserve that an order takes when it enters (01 §12.1). Message fees accrue per
  account in the lane and are debited at each commit point. An account that cannot pay its accrued
  fees gets `RISK_CREDIT` on new messages until it allocates more.

### 12.2 Distribution

All fees of epoch e go to that epoch's fee pool. At the end of e + 1 (after every block of e is
final and the evidence for e has had one epoch to arrive), the pool is split:

| Share | Recipient |
|---|---|
| `CHN_FEE_INS_SHARE` = 10%, until the fund reaches `CHN_INS_TARGET` | insurance fund |
| `CHN_FEE_SEQ_SHARE` = 25% | the sequencing operator(s) of e, pro rata to the book blocks each signed |
| the rest | the 5 operators, pro rata to the chain blocks of e whose finalization certificate contains their signature |

A sequencer that is slashed in e or e + 1 forfeits its share to the insurance fund. Operators earn
nothing for epochs in which they only follow. Their follower nodes are a cost of being allowed to
sequence and vote in the other homes.

### 12.3 Costs

| Item, per node | Colo (reference) | AWS |
|---|---|---|
| Inbound log into the validator box, 33 GB/s peak | flat: metro waves and cross-connects, priced per port per month | cross-AZ transfer at $0.02/GB for both sides together (vendor): about $57k per day at sustained peak, about $5.7k per day at 10% average |
| Log to the 2 follower homes over the WAN | leased waves, flat | inter-region transfer per GB (vendor price needed, §19) |
| Hot storage, 2.0 PB per copy | ~65 NVMe drives (budget) | instance storage or EBS at per-GB-month prices (vendor) |
| Validator box | `REF` box (01 §10) | the `AWS` target (01 §10), one NUMA node |
| Commit box | 32-core COTS server | a 32-vCPU instance |

The traffic cost decides the deployment. At sustained peak, AWS transfer alone is about $21M per
validator per year. In colo the same traffic costs a fixed monthly port fee. So the reference chain
deployment is colo, and AWS is supported for followers, development and small books (C-ONEBIN).

## 13. Front-running by the sequencer

### 13.1 It cannot be prevented at 1 µs

The sequencer sees every packet in plaintext before it orders it. Preventing it from acting on that
needs either threshold decryption (at least one metro round trip of 0.5–1 ms plus tens of µs of CPU)
or commit-reveal (two round trips). Both cost 100 to 1,000 times the 1 µs budget. Detecting it order
by order is impossible too: the cut has 100 ns granularity (01 §14.3) and NIC timestamps have jitter, so a
single reordering of a few hundred ns looks like normal operation.

What a byzantine sequencer can do: put its own order ahead of a client order it has seen, delay a
client packet by microseconds, and write `rx_ts` values of its choosing. What it cannot do: change a
client order, forge one, censor beyond §7, or move a boundary.

### 13.2 Mitigations

1. **Rotation.** An operator sequences 1 epoch in 5, and every (home, operator) pair once in 5 days
   (§3.1). A front-running operator gets at most 20% of the flow.
2. **Bond.** `CHN_SEQ_BOND` is slashed for every provable fault (§8). Statistical evidence is not
   proof, so for front-running the bond is what governance can take after a jail and a replacement.
3. **Independent timestamps.** A client sends its data copy to a data node of an operator other than
   the sequencer. Those data nodes timestamp packets with their own PTP-synced NICs. The sequencer
   cannot change those timestamps.
4. **Published statistics** with fixed definitions (§13.3), so every client can compare sequencers.

### 13.3 Fill-quality statistics

**Sampling.** Each data node of an operator j ≠ s records `DataStamp { pkt_hash, data_rx_ts }` for a
sample of packets:

```
K_sample(e, s) = derive_key("vyrn      v1 sample key", G(e, s).private ‖ le(e) ‖ [s])
sampled(p)     = BLAKE3(derive_key("vyrn      v1 sample", K_sample(e, s)) ‖ pkt_hash)[0]
                 < 256 / CHN_FR_SAMPLE                                     // 1 in 64
```

Only committee members know `K_sample` during the epoch, so the sequencer cannot treat sampled
packets differently. Members disclose `K_sample(e, s)` at the end of the epoch, so anyone can check
the sample.

**Metrics,** per (epoch, home, sequencer), computed by each committee member over its own stamps:

| ID | Metric | Definition |
|---|---|---|
| FQ-1 | Delay skew | δ(p) = `seq_rx_ts(p) − data_rx_ts(p) − median δ of p's session in the epoch`. `SKEW = p99(δ over cross packets) − p99(δ over join packets)`. An honest sequencer cannot delay by class before it parses, so its SKEW is about 0. Flag above `CHN_FR_SKEW_NS` (500 ns). |
| FQ-2 | Fast-taker markout | For sessions with ≥ `CHN_FR_FAST_FILLS` (1,000) taker fills in the epoch: notional-weighted mean of `side × (mid at the first step with rx_ts ≥ fill rx_ts + 1 ms − fill price)`, in ticks. Report the z-score against the trailing 15 epochs of the same home. Flag at z < −3. |
| FQ-3 | Inversion rate | Pairs of crosses from different accounts on the same side, both sampled, both reaching the same best level, where the later-executed one has a `data_rx_ts` at least `CHN_FR_INV_NS` (1 µs) earlier. Per million crosses. Flag above 3× the trailing median. |
| FQ-4 | Bust rate | Excluded packets per billion packets, and the time from the second `TagFault` to the suspension (§5.8). |

Each member publishes `SeqStats { epoch, home, seq_op, reporter: OpIdx, fq1..fq4, n_samples }`
signed with its node key in the public log, and an item with its hash on chain. FQ-2 and FQ-4
use only certified log data, so every reporter must publish the same values. FQ-1 and FQ-3 use the
reporter's own stamps, so values differ between reporters within sampling error.

**Consequence.** There is no automatic slash. If at least 2 reporters flag FQ-1 or FQ-3 for one
operator in 3 of the last 5 epochs it sequenced, the other operators are expected to `Jail` it
(tightening, immediate) and to start its replacement. The rule is published so that clients can
check it was followed.

## 14. Upgrades

### 14.1 Versions

`ProtoVer { major: u16, minor: u16 }`. The chain keeps a version table: the state-transition version
in force for each epoch. A version changes only at an epoch boundary, by an `Upgrade` action, with
the 72 h timelock. `release_hash` is the BLAKE3 hash of a release manifest that lists the build hashes
of the Rust validator, the Vx validator and `vyrn-seq`.

### 14.2 Coordinated activation for both clients

1. Governance approves `Upgrade { proto, release_hash }` with an `activation` epoch.
2. Each operator installs the release on every node, and each validator box submits
   `ReadySignal { proto, client_kind, build_hash }` signed by its node key.
3. At `activation − 1`, the state machine checks readiness: at least `Q_CHAIN` (4) operators have
   signaled for their node in `home(activation)`. If yes, the version table entry is fixed. If no,
   the activation moves 3 epochs later (the same home, one day on). After 3 moves it is cancelled.

Because Rust validators are 3 operators and the quorum is 4, an upgrade cannot activate unless at
least one Vx operator is ready. So a release that only one client implements cannot take effect,
the same property that `CLIENT_SPLIT_CHAIN` gives finality.

### 14.3 The version handshake

Every p2p connection starts with the transport handshake, hybrid X25519 + ML-KEM-768 from `E_pq`
(01 §14.20 G, PQ-12), and then:

```
Hello { chain_id: u32, genesis_hash: Hash, op: OpIdx, home: HomeCode, client_kind: u8,
        build_hash: Hash, proto_min: ProtoVer, proto_max: ProtoVer, epoch: Epoch,
        version_table_hash: Hash, sig: Ed25519 by NK }
```

A node refuses the connection if `chain_id` or `genesis_hash` differ, if no version in
`[proto_min, proto_max]` matches the version in force for the current epoch, or if
`version_table_hash` differs. The last check catches two nodes that disagree about governance before
they disagree about a block. Client protocol versions on the order path belong to `04-protocol.md`.

### 14.4 History stays replayable

Every released binary keeps the state-transition code of every earlier version and selects it by
the version table. Replaying epoch e uses `version_table[e]`, so `INV-DET` holds across upgrades.

### 14.5 Emergencies

A fix that does not change the state transition (p2p, DoS, performance) is node-local and needs no
governance. A fix that changes it is an `Upgrade` with the full timelock. If a bug threatens funds,
the operators use `HaltBook` or `pause()` at once (tightening), then ship the fix under the timelock.
No path changes the rules without 72 h of notice.

## 15. Threat model

| Attacker | Capability | Defense | Residual risk |
|---|---|---|---|
| Byzantine sequencer | signs two histories | high-water mark; `SeqEquivocation` slash | clients that saw the losing history get busted fills until failover |
| Byzantine sequencer | forges a client packet | needs `K_com` (§5.6) | none within f = 1 |
| Byzantine sequencer | sends bad-`tag_com` packets of a client | busted; the client's bond pays | one bond per victim session; visible in FQ-4 |
| Byzantine sequencer | front-runs | rotation, bond, FQ-1–FQ-3 | up to 20% of flow, until governance acts |
| Byzantine sequencer | censors a client | forced path (§7), deadline, `Censorship` slash, failover | ≤ 2.4 ms out of the log; final ≤ ~40 ms (`FAILOVER_TARGET_MS` + `FINALITY_MAX_MS` after the deadline) |
| Byzantine sequencer | halts without cause | `CHN_HALT_GRACE_MS`, then silence and failover (§4.6) | ≤ 1 ms of `BOOK_HALTED` plus the failover |
| Byzantine sequencer | keeps trading after T | fence, `FenceViolation`, `HandoffWithheld` | the next home starts ~10 ms later |
| Byzantine sequencer | ignores `TagFault`s | `SESSION_DEAD` busts everything after | more busted fills, visible in FQ-4 |
| Byzantine member | wrong exclusion list as leader | members recompute (§5.6) | one nullified view (≤ 2.8 ms), inside the 8 ms gate (§4.8) |
| Byzantine member | double vote | `DoubleVote` slash, jail | none for safety |
| Byzantine member | leaks `G(e, s)` | needs the sequencer too | none within f = 1 |
| Byzantine member | false `TagFault` / `AnchorFault` | quorum of 2 | none |
| Byzantine member | censors items as leader | next leader includes them | ≤ 1 view |
| Two colluding operators (seq + member) | forge packets | outside the model | trades the honest operators cannot detect live; `WrongExclusion` after disclosure only if they also sign a wrong list |
| Client | bad `tag_com` | exclusion, bust, bond | counterparties keep second-order effects |
| Client | two versions of one packet | `pkt_hash` mismatch kills the session (`07-replication.md`) | none |
| Client | floods the forced path | rate, fee, cheap checks first | none |
| Client | spends proceeds of a busted fill | bust debt, insurance fund | insurance fund loss |
| L1 reorg | undoes a deposit | finalized checkpoints only | requires 1/3 of L1 stake slashed |
| Thief of 4 bridge keys | signs a false post | guardian veto, 1 h challenge, 10% daily cap | up to 10% of TVL per day if every guardian fails |
| Quantum attacker (Shor) | recovers secp256k1 and Ed25519 private keys from public keys | hybrid keys from `E_pq` for every VYRN signature; `pq_anchor`; `SetOwnerKey`, the classical cutoff, a second bridge and `PqAlarm` (§6.8) | the old bridge (up to 10% of TVL per day) and classical owner keys until users migrate |
| Thief of one operator key | governance actions | 4-of-5; the others `Jail` | none |
| Lying RPC server | false balance or history | proofs (§10) | none |
| Long-range attacker | fake history from old keys | weak subjectivity, L1 checkpoint | clients that skip re-anchoring |
| Data withholding | blocks replay | votes require all payloads | liveness only |
| Validators stop entirely | funds stuck | escape hatch after 14 days | 14 days of illiquidity |
| Compiler or client bug | wrong state | 3 Rust + 2 Vx; `CommitCert` divergence alarm | a halt instead of a fork |
| Jailed operator not replaced | — | — | f = 0 for liveness until replacement |
| Network beyond its delay bound, or > F faults | finality stalls | the gate halts the book after 8 unfinal closed blocks (§4.6) | ≤ 9 ms of issued fills final late, none lost (01 §14.0 fact 3) |

## 16. Interfaces to other chapters

| Chapter | This chapter consumes | This chapter provides |
|---|---|---|
| 02 | `REQ-CHN-*`, `REQ-SEC-*` | the mechanisms and numbers those requirements cite; **REQ-CHN-12 must read "the gate never binds with ≤ F faults" (B-CHN-3), and 02's CHAIN unfinalized-depth bound must cite D = 8, not 16** |
| 03 | the box roles and core maps | the commit box (§9.6); core budgets for `tag_com` (4) and hashing (5) on the validator box; **each operator's primary data box in its F2–F5 facility and backup in another of F2–F5, never a primary in F1 (§4.8, 01 §14.16)**; one standby per epoch, the F2 box of `next_seq` (§3.2) |
| 04 | session protocol, failover notice, gap rules | chain-mode session open (§5.2), key derivation (§5.3), the interval choice (§5.4); **04 must accept a forced packet out of order (§7.3)** |
| 05 | lanes, the cut, `INV-DET`, the fill ring, deadline admission | `ItemRecord`, the boundary rule and `CHN_ITEM_OPS_PER_BLOCK` (§4.6); the gate halt and its `Control` steps (§4.6); bust ops as net ops (§5.9); dirty marks and LtHash diffs (§9.3, §9.4); session suspension op (§5.8); forced packets injected from the control core (§7.1) |
| 06 | Linux, NIC backends, PTP | none beyond C-UNIX and C-NOCHIP compliance (§1.1) |
| 07 | Simplex, payload availability, the order stream, failover | the `ChainBlock` and voter checks (§4.3), the custom leader schedule (§4.3), `INV-CHN-TXGATE` and the halt (§4.6), exclusion lists (§5.7), the log hash (§9.2); **07 sends finalize votes to the live and standby sequencer boxes and counts the gate in closed blocks (07 §6.8); it must home sessions on F2–F5 data boxes (§4.8, 07 §5.1), treat a missed item deadline or an unjustified halt as silence, and finalize the failover seal ≤ 9 ms after the last frame** |
| 08 | handoff, `HomeOverride`, failover detection | `next_keys` in `HandoffRecord` (§10.2), `HandoffTimeout` (§8.3), sequencer schedule (§3.1) |
| 10 | accounts, lanes per account, risk, fees, market data | allocations, bust debt, fee classes (§12.1), book height in market data (§5.4) |
| 11 | benchmarks, `vyrn-sim`, the Vx oracle | B-CHN-1 to B-CHN-6 (§19), the divergence drill (§9.5) |

## 17. Local definitions

### 17.1 Constants

All values are budgets and governance parameters unless marked otherwise.

| Name | Value | Meaning |
|---|---|---|
| `FIN_GATE_BLOCKS` (D) | 8 (01 §14.9, fixed) | Gate depth in closed blocks; the item deadline is D + 1 blocks after `lastb(C)` (§4.6) |
| `CHN_HALT_GRACE_MS` | 1 | A halt that outlasts the gate's condition by this much is silence (§4.6) |
| `CHN_ITEM_OPS_PER_BLOCK` | 16 | Item ops per lane per boundary; the rest carry (§4.6) |
| `CHN_TESLA_PEBBLES` | 15 | Traversal state per (session, e, s) on a member (§5.4) |
| `CHN_KEY_LEAD_EPOCHS` | 4 | Lead time of `NodeCert`s, committee keys and the sequencer schedule |
| `CHN_SESSION_MAX_EPOCHS` | 3 | Longest session lifetime |
| `CHN_TESLA_BLOCKS` | 1,000 | Book blocks per TESLA interval (~1 s) |
| `CHN_TESLA_N` | 28,800 | Intervals per epoch; hash-chain length |
| `CHN_GOV_TIMELOCK_EPOCHS` | 9 | 72 h timelock for loosening actions |
| `CHN_UNBOND_EPOCHS` | 63 | 21 days |
| `CHN_EVIDENCE_EPOCHS` | 42 | 14 days |
| `CHN_WS_EPOCHS` | 42 | Light-client weak-subjectivity period |
| `CHN_JAIL_REPLACE_EPOCHS` | 9 | Time by which a jailed operator's replacement must start |
| `CHN_OPERATOR_BOND` | 20,000,000 USDC | Per operator |
| `CHN_SEQ_BOND` | 10,000,000 USDC | Per sequenced epoch |
| `CHN_SESSION_BOND_MIN` | 1,000 USDC | Floor of the session bond |
| `CHN_BOND_PER_MSGRATE` | 0.01 USDC | Session bond per message per second of rate limit |
| `CHN_TAGFAULT_QUORUM` | 2 | Distinct operators to suspend a session |
| `CHN_ANCHORFAULT_QUORUM` | 2 | Distinct operators to mark `NoKey` |
| `CHN_ATTEST_QUORUM` | 3 | Distinct operators to credit an L1 event |
| `CHN_MAX_ITEMS` | 500 | Items per chain block |
| `CHN_MAX_ITEM_BYTES` | 262,144 | Item bytes per chain block |
| `CHN_TX_RATE` | 10 | Items per second per signer |
| `CHN_TX_PORT` | configuration (default 9443) | QUIC port of the transaction path |
| `CHN_BUST_COMP_BPS` | 10 | Bond payout per busted counterparty fill |
| `CHN_DEBT_GRACE_S` | 3,600 | Time to repay a bust debt |
| `CHN_DISCLOSE_PERIOD_S` | 10 | Client disclosure period |
| `CHN_COMMIT_BLOCKS` | 1,000 | Chain blocks per `StateCommit` |
| `CHN_COMMIT_LAG_MS` | 500 | `CommitCert` on chain after its second |
| `CHN_POST_S` | 60 | L1 post period when withdrawals are pending |
| `CHN_CHECKPOINT_S` | 3,600 | L1 post period otherwise |
| `CHN_CHALLENGE_S` | 3,600 | Challenge period of a post |
| `CHN_VETO_OVERRIDE_S` | 259,200 | 72 h before a 4-of-5 override of a veto |
| `CHN_BRIDGE_ROTATE_S` | 259,200 | L1 delay of a signer rotation |
| `CHN_BRIDGE_DAILY_CAP_BPS` | 1,000 | Outflow cap per token per 24 h |
| `CHN_ESCAPE_S` | 1,209,600 | 14 days without an accepted post |
| `CHN_FORCED_RATE` | 100 | Forced packets per second per session |
| `CHN_HANDOFF_DEADLINE_MS` | 10 | After T, before `HandoffTimeout` |
| `CHN_REPORTER_SHARE` | 500 bps | Share of a slash paid to the reporter |
| `CHN_HOT_DAYS` | 7 | Hot log retention per operator |
| `CHN_ARCHIVE_YEARS` | 7 | Archive retention |
| `CHN_SNAPSHOT_S` | 3,600 | Snapshot period |
| `CHN_REPLAY_SPEEDUP` | 2 | Replay rate / peak live rate |
| `CHN_LTHASH_DIM` | 1,024 × u16 | LtHash vector |
| `CHN_FEE_TAKER_BPS`, `CHN_FEE_MAKER_BPS` | 2.0, 0 | Fill fees |
| `CHN_FEE_IMPROVE`, `CHN_FEE_MSG` | 10 µUSDC, 0.1 µUSDC | Message fees |
| `CHN_FEE_TX`, `CHN_FEE_FORCED`, `CHN_FEE_SESSION` | 0.01, 0.01, 1 USDC | Item fees |
| `CHN_FEE_INS_SHARE`, `CHN_FEE_SEQ_SHARE` | 10%, 25% | Fee split |
| `CHN_INS_TARGET` | 50,000,000 USDC | Insurance fund target |
| `CHN_FR_SAMPLE` | 64 | 1 in 64 packets stamped by data nodes |
| `CHN_FR_SKEW_NS`, `CHN_FR_INV_NS` | 500, 1,000 | FQ-1 and FQ-3 thresholds |
| `CHN_FR_FAST_FILLS` | 1,000 | FQ-2 session threshold |

### 17.2 Types and records

`OpIdx` (u8), `OwnerKey`, `OperatorEntry`, `NodeCert` (§2.3), `CommitteeKey` (§2.4), `VoteMsg`
(§2.5), `GenesisRecord` (§2.7), `GovAction`, `GovKind` (§2.10), `ChainHeader`, `BookEntry`,
`ChainBlock` (§4.3), `TxEnvelope`, `SignerRef` (§4.4), `SessionOpen` (§5.2), `ExclusionList`,
`ExclEntry` (§5.7), `TagFault` (§5.8), `AnchorFault` (§5.4), `KeyDisclosure` (§5.10),
`ForcedPacket` (§7.2), `L1Attest`, `L1Event` (§6.3), `Post`, `Withdrawal` (§6.2), `Evidence`
(§8.2), `HandoffTimeout` (§8.3), `StateCommit`, `CommitVote`, `CommitCert` (§9.5), the SMT leaves
(§9.3), `EpochKeys` (§10.2), `Receipt` (§10.3), `DataStamp`, `SeqStats` (§13.3), `ProtoVer`,
`ReadySignal`, `Hello` (§14).

One new order-stream record, logged by the lane at the op where it applies something that did not
arrive as a packet:

```
ItemRecord { lane: LaneId, kind: u8,          // 1 item, 2 bust op, 3 suspension, 4 forced hint
             chain_height: Height,            // the chain block that scheduled it; 0 for a hint
             index: u16,                      // item index, or exclusion entry index
             lane_seq: LaneSeq, result: u16 } // 0 applied; otherwise a reject reason (01 §6.5, §14.10)
```

The gate uses `StepKind::Control` (01 §14.10) with sub-code 1 *halt* and 2 *gate open* (§4.6).
The `Bust` record (0x87, 01 §14.10) has the `Fill` layout: `type, index = 0xFF, liq, handle, tick,
qty`, where `qty` is the reversed quantity of the original fill.

### 17.3 Derivation and signing contexts

| Context | Used for |
|---|---|
| `"vyrn v1 session"` | `K_seq`, `K_out` (01 §4) |
| `"vyrn v1 kcom head"`, `"vyrn v1 kcom"` | TESLA chain head; `K_com` per interval |
| `"vyrn v1 gkey wrap"` | Transport of committee private keys |
| `"vyrn v1 sample key"`, `"vyrn v1 sample"` | `K_sample`; the FQ sample predicate |
| `"vyrn v1 vote"`, `"vyrn v1 commit"`, `"vyrn v1 seqsig"` | Consensus votes, commit votes, `seq_sig`. Under a hybrid scheme each part signs `scheme ‖` this message (01 §14.20) |
| `"vyrn v1 nodecert"`, `"vyrn v1 gov"`, `"vyrn v1 tx"` | Certificates, governance, items |
| `"vyrn v1 genesis"`, `"vyrn v1 log"`, `"vyrn v1 epochkeys"` | Genesis hash, log hash, key-table hash |
| `"vyrn v1 smt leaf"`, `"vyrn v1 smt node"` | SMT hashing |
| `"vyrn v1 lthash"`, `"vyrn v1 lthash digest"` | LtHash element and digest |

### 17.4 Invariants

| Name | Statement |
|---|---|
| `INV-CHN-SPLIT` | An operator's consensus and commit votes are cast by its validator box, which runs its client kind, never by its sequencer box. No sequencer box, live or standby, holds a `G` private half (01 §14.4). |
| `INV-CHN-ONEVOTE` | Per `(epoch, view)`, an operator signs at most one `Notarize`, at most one `Finalize`, and never a `Finalize` and a `Nullify`. |
| `INV-CHN-KEYSPLIT` | No operator other than s can compute `K_seq(e, s)`; s cannot compute `K_com(e, s, ·)` before its disclosure. |
| `INV-CHN-TXGATE` | The sequencer never runs more than D = 8 closed blocks ahead of finality: it applies no op of book block h until it holds a finalization that covers book block h − D − 1, and halts until then (01 §14.9, 07 §6.8). |
| `INV-CHN-EXCL` | An exclusion list is a pure function of chain state, the book block and its payloads. |
| `INV-CHN-NOMINT` | Per asset, total state balances equal credited deposits minus withdrawals in posts. Only a credited deposit creates an asset in state. |

## 18. Requests to 01

1. **§4, `K_com`:** derive it via X25519 with the per-epoch committee key `G(e, s)` (§2.4), not with
   each validator's static key, so that all 4 holders get one key. Add the contexts of §17.3.
2. *Resolved by 01 §14.11:* keccak256 and secp256k1 EIP-712 only for the parts that face L1.
3. **§4, session open:** the session also registers an Ed25519 session signing key (`sign_pub`),
   used by forced packets and small transactions (§5.2, §7.2).
4. **§6.6, `HandoffRecord`:** add `next_keys: Hash` = `keys_hash(e + 1)` (§10.2).
5. **§6.6:** state that `BlockHeader.height` is a per-book height; add `ChainHeader` (§4.3) and
   `ItemRecord` (§17.2) to the order-stream records.
6. *Resolved by 01 §14.10:* `0x87 Bust`. Remaining: copy its layout (§17.2) into §6.4.
7. *`CHN_TX_DELAY_BLOCKS` resolved by 01 §14.9 as `FIN_GATE_BLOCKS` = 8.* Remaining: promote
   `CHN_TESLA_BLOCKS`, which 04 and 07 depend on.
8. **§3:** add the type `OpIdx` (u8).
9. *`INV-CHN-KEYSPLIT` resolved by §14.11; `INV-CHN-SPLIT` and `INV-CHN-TXGATE` in substance by
   §14.4 and §14.9.* Remaining: list both by name in §7, with the `G`-key rule of `INV-CHN-SPLIT`.
10. **§1:** add the terms operator, node (one operator's boxes in one home), committee, chain block,
    book height, chain height and bust.
11. **§14.9:** *Resolved by 01:* its last bullet says `FINALITY_MAX_MS`, the name §5 uses.
12. **§6.5:** fix the `detail` of `BOOK_HALTED`: 1 = chain gate (§4.6), 2 = `HaltBook`. Fix the
    `Control` sub-codes 1 *halt* and 2 *gate open* with §14.10's `StepKind::Control`.
13. **§14.9:** state that `FIN_GATE_BLOCKS` counts closed blocks (block h + 9 opens only when h is
    final) and that an item's deadline is `lastb(C) + FIN_GATE_BLOCKS + 1`. With §14.16's data
    home outside F1, the one-fault worst case is 8.11 ms from block start (§4.8), past the 8.00 ms
    that the open-block count allows; 07 §6.8 already needs the closed count for BASE.
14. *Resolved by 01 §14.16:* the data home. 09 places each operator's primary data box in its
    F2–F5 facility (§4.8).

## 19. Open questions

| # | Question | Owner | Settled by |
|---|---|---|---|
| 1 | Does one `REF` box hold replay plus `tag_com` (4 cores) plus hashing (5 cores) plus the TESLA traversal (§5.4)? Is 20 µs the right Ed25519 planning figure on `REF`? | 03 | B-CHN-1: validator box at `WL-REF` (145.5M packets/s) with tags and hashes on |
| 2 | The real net-diff rate of resting orders per second, and the LtHash cost per element with AVX-512 | 09, 11 | B-CHN-2: LtHash workers on a recorded quote-driven flow |
| 3 | D = 8 is fixed (01 §14.9). Does the one-fault worst case stay ≤ 9 ms from block start in the real metro, with data homes in F2–F5? The budget is 8.11 ms, margin 0.89 ms (§4.8). | 07, 03 | B-CHN-3: 24 h in a 5-facility metro at `WL-REF`, with an injected leader fault and a data box failure; the gate never binds |
| 4 | Can Commonware Simplex take a custom leader function (committee minus the sequencing operator) and one instance per epoch? | 07 | A `vyrn-sim` test with the leader function and a failover |
| 5 | Gas of BLAKE3 SMT proofs in Solidity for `escapeClaim` | 09 | B-CHN-4: Foundry gas report of `escapeClaim` with a 27-sibling proof |
| 6 | Frequency of bust debt, and whether `CHN_INS_TARGET` covers the worst day | 10 | `vyrn-sim` with adversarial clients sending bad `tag_com` into fast counterparties |
| 7 | Inter-region transfer price for follower homes (AWS) and transoceanic wave prices (colo) | 08 | Vendor quotes recorded in 08 |
| 8 | zstd ratio of payloads in the archive | 11 | B-CHN-6: compress one recorded hour |
| 9 | False-positive rate of FQ-1–FQ-3 with an honest sequencer, and detection power against a simulated front-runner | 11 | B-CHN-5: `vyrn-sim` with an injected 300 ns front-running strategy |
| 10 | The SMT and LtHash code on the commit box is Rust for every operator. Is that a common-mode risk that needs a Vx implementation? | 11 | Review after B-CHN-2; diff test of both if built |
| 11 | How many BUSY sheds do item ops at block boundaries cause, and is `CHN_ITEM_OPS_PER_BLOCK` = 16 right? | 05 | B3 with a bust over 10k accounts and 500 items per chain block |
| 12 | When does `CHN_PQ_OWNER_CUTOFF` take effect (§6.8)? The bridge and `PqAlarm` triggers are decided (01 §14.20 PQ-5). | owner | at or after `PqAlarm`, once hybrid `OwnerKey` wallets are available |
