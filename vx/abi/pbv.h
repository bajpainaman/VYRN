/* C ABI shared by Rust and Vx: structs, rings, entry points (spec/11-build.md §5.1).
 * Libraries export only pbo_* (oracle) and pbv_* (client) symbols; vx/build.sh checks with nm -D.
 *
 * Every integer is little-endian. Every field named reserved* must be 0 on input and is 0 on
 * output; a nonzero reserved field is a malformed input, so later versions can give it a meaning.
 * Each struct has a static size check below; the Rust side repeats it. */
#ifndef VYRN_PBV_H
#define VYRN_PBV_H

#include <stddef.h>
#include <stdint.h>

/* ===================================================================================== */
/* Oracle: vyrn-vx-oracle, the sequential reference book (11 §5.2, 05 §2).               */
/* ===================================================================================== */

/* Bumped on any change to a layout, an event kind or a record rule in this section. */
#define PBO_ABI_VERSION 1u

typedef struct pbo_book pbo_book;

/* Book parameters. Offsets are fixed: 0 abi_version, 4 size, 8 band_lo, 12 band_hi,
 * 16 quote_per_tick_lot, 24 max_fee_ppm, 28 min_qty, 32 max_order_qty, 36 max_open_per_acct,
 * 40 max_orders, 44 phase, 45 reserved8, 48 reserved, 80 lane_rank, 144 lane_first_handle. */
typedef struct {
    uint32_t abi_version;          /* PBO_ABI_VERSION */
    uint32_t size;                 /* sizeof(pbo_config) */
    uint32_t band_lo, band_hi;     /* price band, inclusive ticks (05 §13.2) */
    uint64_t quote_per_tick_lot;   /* px(t) = t * quote_per_tick_lot (05 §2.6) */
    uint32_t max_fee_ppm;          /* sizes buy reservations; every account rate <= it (10 §5) */
    uint32_t min_qty;              /* ENG_MIN_QTY */
    uint32_t max_order_qty;        /* ENG_MAX_ORDER_QTY, <= 2^31 - 1 */
    uint32_t max_open_per_acct;    /* ENG_MAX_OPEN_PER_ACCT */
    uint32_t max_orders;           /* capacity of the oracle's order table, every order ever entered */
    uint8_t  phase;                /* initial phase, PBO_PHASE_* */
    uint8_t  reserved8[3];
    uint32_t reserved[8];
    uint8_t  lane_rank[64];        /* rank_e(lane) of the epoch, the middle of PrioKey (05 §3.2) */
    uint32_t lane_first_handle[64];/* first Handle each lane gives out (slot 1 ..= 2^24 - 2, any
                                      generation); later handles take the next slot, same generation */
} pbo_config;                      /* 400 bytes */

/* One account. pbo_new requires accounts sorted by strictly ascending id. */
typedef struct {
    uint32_t id;                   /* AccountId */
    uint8_t  lane;                 /* the lane that owns the account's handles and balances */
    uint8_t  reserved8[3];
    int32_t  maker_ppm;            /* fee rates, parts per million of notional; negative = rebate */
    int32_t  taker_ppm;
    int32_t  auction_ppm;
    uint32_t reserved;
    uint64_t base_free;            /* lots */
    uint64_t quote_free;           /* quote atomic units */
} pbo_account;                     /* 40 bytes */

typedef struct {
    uint32_t session;              /* SessionId */
    uint32_t account;              /* AccountId of an entry in the account table */
} pbo_session;                     /* 8 bytes */

/* Event kinds. The harness turns the order stream into these, in the linear order L (05 §3,
 * 11 §6.3): lane-local ops at their LaneSeq, BBO-bound ops at their step. */
enum {
    PBO_EV_MSG = 1,       /* apply msg at its position in L; fills carry `step` */
    PBO_EV_STEP = 2,      /* arg = StepKind (vyrn-types codes). Shed: answer msg Reject BUSY and
                             change nothing. Rescan, Depletion, Idle: no-op. Others: PBO_E_EVENT. */
    PBO_EV_PHASE = 3,     /* Control step: arg = PBO_PHASE_* */
    PBO_EV_UNCROSS = 4,   /* the auction uncross (08 §7.6); msg bytes 0-3 = ref tick; then Continuous */
    PBO_EV_EPOCH_END = 5, /* reserved; PBO_E_EVENT in v1 */
};

enum { PBO_PHASE_CONTINUOUS = 1, PBO_PHASE_AUCTION = 2, PBO_PHASE_HALTED = 3, PBO_PHASE_FROZEN = 4 };

/* One linearised event. Offsets: 0 kind, 1 lane, 2 index, 3 arg, 4 session, 8 pkt_seq,
 * 12 reserved, 16 rx_ts, 24 step, 32 lane_seq, 40 msg. */
typedef struct {
    uint8_t  kind;                 /* PBO_EV_* */
    uint8_t  lane;                 /* the op's lane (rank and key) */
    uint8_t  index;                /* message index in its packet, 0..9 */
    uint8_t  arg;                  /* StepKind for STEP, phase for PHASE, else 0 */
    uint32_t session;
    uint32_t pkt_seq;
    uint32_t reserved;
    uint64_t rx_ts;                /* prio_ts of the op's key (Nanos) */
    uint64_t step;                 /* StepId the op is positioned at; 0 for a lane-local op */
    uint64_t lane_seq;             /* LaneSeq of the op, the last part of its key */
    uint8_t  msg[16];              /* 01 §6.2 message bytes (MSG, STEP Shed); UNCROSS: ref tick */
} pbo_event;                       /* 56 bytes */

/* One response record. rec holds the 01 §6.4 bytes unchanged. */
typedef struct {
    uint32_t session;              /* the session the record is for */
    uint32_t reserved;
    uint64_t step;                 /* the event's step; 0 for a lane-local op */
    uint8_t  rec[16];              /* 01 §6.4 bytes */
} pbo_record;                      /* 32 bytes */

/* pbo_apply results other than a record count. After PBO_E_CAP the book has applied the
 * event, so the caller must not continue with it. */
#define PBO_E_CAP   UINT32_MAX         /* out_cap too small */
#define PBO_E_EVENT (UINT32_MAX - 1u)  /* malformed event: kind, reserved field, unknown session */
#define PBO_E_FULL  (UINT32_MAX - 2u)  /* order table full (max_orders); nothing applied */
#define PBO_E_FAULT (UINT32_MAX - 3u)  /* a balance overflowed after entry: an engine fault (10 §4.5) */

/* Record rules (05 §2.4, §2.7; 04 §6, §7.3):
 * - One record list per event. Each session's records are in the order that session's client
 *   sees them; that is the order a harness compares. Across sessions the order is: a maker's
 *   record when its fill or STP removal happens, the taker's merged Fill when its level ends.
 * - Within the session that sent a message, all of the message's records come before that
 *   session's own maker records of the step (04 §7.1 numbering rule, §7.2 R-MAKER).
 * - Every New and priority-losing Replace that passes the lane checks takes its account's lane's
 *   next handle, also when it never rests (IOC, FOK, STP, post-only reject at the book).
 * - CancelAll (04 §6.6, vector V15): one CancelAck per live order of the session in ascending
 *   handle order, then the summary CancelAck(0xFFFFFFFF, count), all with its index and tag.
 * - Replace (04 §6.5, vector V4): a priority-losing Replace gives the new order a new handle.
 * - STP cancel-newest and cancel-both before any fill: Reject STP, detail = the resting handle;
 *   after a fill: Out STP (04 §6.8).
 * - Fees are ppm of notional (10 §5): ceil for a charge, floor for a rebate. A maker or auction
 *   fill pays per fill; a taker pays once per step on the step's total notional (10 §3.3, §4.4).
 * - Post-only New and Replace outside Continuous: Reject AUCTION_PHASE, detail the phase (04 §6.9). */

/* Canonical state bytes, version 1 (05 §2.8):
 *   header 32 B: 0 magic 0x31534250 ("PBS1"), 4 u16 version 1, 6 u8 phase, 7 u8 0,
 *                8 band_lo, 12 band_hi, 16 u64 last StepId, 24 u32 orders, 28 u32 accounts
 *   orders, 48 B each, resting only, sorted by (side buy first, tick, PrioKey):
 *                0 handle, 4 account, 8 session, 12 u8 flags (01 §6.2), 13 u8 lane, 14 u8 rank,
 *                15 u8 0, 16 tick, 20 total, 24 filled, 28 client_tag, 32 u64 rx_ts, 40 u64 lane_seq
 *   accounts, 48 B each, by AccountId: 0 id, 4 open_orders, 8 base_free, 16 base_resv,
 *                24 quote_free, 32 quote_resv, 40 u64 0
 *   fee accumulators: 64 x i64, fee_acc[lane] (05 §2.6)
 * Per-session resp_seq is packetization and is not part of the oracle (records, not packets). */

uint32_t  pbo_abi_version(void);
/* NULL when cfg is malformed: version, size, reserved fields, band, account order, rates. */
pbo_book* pbo_new(const pbo_config* cfg, const pbo_account* accounts, uint32_t n_accounts,
                  const pbo_session* sessions, uint32_t n_sessions);
uint32_t  pbo_apply(pbo_book* b, const pbo_event* ev, pbo_record* out, uint32_t out_cap);
/* Returns the size of the state; writes it only when cap is at least that size. */
uint64_t  pbo_state_bytes(const pbo_book* b, uint8_t* out, uint64_t cap);
void      pbo_free(pbo_book* b);

#define PBV_STATIC_ASSERT(c, m) typedef char m[(c) ? 1 : -1]
PBV_STATIC_ASSERT(sizeof(pbo_config) == 400, pbo_config_is_400_bytes);
PBV_STATIC_ASSERT(sizeof(pbo_account) == 40, pbo_account_is_40_bytes);
PBV_STATIC_ASSERT(sizeof(pbo_session) == 8, pbo_session_is_8_bytes);
PBV_STATIC_ASSERT(sizeof(pbo_event) == 56, pbo_event_is_56_bytes);
PBV_STATIC_ASSERT(sizeof(pbo_record) == 32, pbo_record_is_32_bytes);
PBV_STATIC_ASSERT(offsetof(pbo_config, lane_first_handle) == 144, pbo_config_handle_offset);
PBV_STATIC_ASSERT(offsetof(pbo_event, msg) == 40, pbo_event_msg_offset);

/* ===================================================================================== */
/* Client: vyrn-vx-client, the replay-only validator engine (11 §5.3, 07 §7.1).         */
/* ===================================================================================== */

/* Bumped on any change to a layout, a ring, an error code or the supported subset. */
#define PBV_ABI_VERSION 3u

typedef struct pbv_ctx pbv_ctx;

/* Tables, by byte offset (the client reads them byte by byte, so no struct layout is assumed).
 * pbv_config, 64 bytes: 0 abi_version u32 (PBV_ABI_VERSION), 4 size u32 (64), 8 n_lanes u8
 *   (1..=64), 10 book u16, 12 epoch u32, 16 tick_min u32, 20 tick_max u32, 24 tick_size u64,
 *   32 band_bps u32 (<= 10000), 36 slot_cap u32, 40 seg_cap u32, 48 pool u64 (pooled lanes,
 *   bit l); the rest reserved.
 * pbv_account, 80 bytes: 0 slot u32 (AcctSlot), 4 lane u8, 5 state u8 (0 active, 1 killed,
 *   2 closed), 6 has_pool_ix u8, 8 max_open u32, 12 max_qty u32, 16 max_notional u64, 24 taker_ppm i32,
 *   28 maker_ppm i32, 32 auction_ppm i32, 36 msg_fee_improve u32, 40 msg_fee_cross u32,
 *   44 pool_ix u32 (pool-wide index, STP across pooled lanes), 48 base_free u64,
 *   56 quote_free u128 (low word first).
 * pbv_session, 32 bytes: 0 id u32 (SessionId; its lane is bits 12..20), 4 acct slot u32,
 *   8 book u16, 10 pooled u8, 12 pooled account u32 (AccountId; each record takes an AcctTake),
 *   16 k_seq[16]. */

/* The shared region (pbv_shared): pbv_shared_bytes(n) bytes, 128-aligned and zeroed, owned by
 * the Rust shell. It starts with 1 + 4(n + 1) control lines of 16 u64 words; each word has one
 * writer, read and written with acquire/release.
 *   line 0         w0 stop (shell)
 *   line 1 + 4l    lane l in_head (shell): w0 records written, w1 the count w0 reaches once the
 *                  block's records are all written (an empty ring below it is not exhausted)
 *   line 2 + 4l    lane l in_tail (client): w0 records replayed, w1 the in_head it last saw idle,
 *                  w2 the step its next call waits for, w3 PBV_E_*, w4 the record index (err_at)
 *   line 3 + 4l    lane l out_head: w0 responses written (client)
 *   line 4 + 4l    lane l out_tail: w0 responses read (shell)
 *   line 1 + 4n    step_head: w0 steps written (shell)
 *   line 2 + 4n    step_tail (client): w0 steps run, w1 last step done, w2 PBV_E_*, w3 the step
 *   line 3 + 4n    tx_head: w0 TX packets written (client)
 *   line 4 + 4n    tx_tail: w0 TX packets read (shell)
 * Then the rings, each PBV_SLOTS slots, in this order: n input rings, n output rings, the step
 * ring, the TX ring. Slot i of a ring is counter i mod PBV_SLOTS. */
#define PBV_SLOTS      1024u
#define PBV_IN_BYTES    512u /* 0 lane u8, 1 count u8, 2 flags u8, 3 n_routes u8 (<= 10),
                                4 session u32, 8 pkt_seq u32, 12 payload_len u32, 16 rx_ts u64,
                                24 pkt_hash u64, 32 first_lane_seq u64, 40 fills_applied u64,
                                48 record index u64 (for errors), 56 snap_lag u16 (0 on an
                                Advance or SHED record), 64 routes (16 bytes each:
                                lane_seq u64, cross u8), 224 payload (<= 192), 416 AcctTake:
                                has u8, 417 predecessor lane u8, 420 account u32, 424 ver u32,
                                428 predecessor ver u32 (0: none). One slot per PacketRecord,
                                MID and Advance records included, in O-order; a packet's
                                RouteRecords ride in its slot. */
#define PBV_OUT_BYTES   288u /* 0 session u32, 4 resp_seq u32, 8 echo_pkt u32, 12 n u8,
                                13 n x record[16]: exactly the bytes H(lane l) hashes */
#define PBV_STEP_BYTES  576u /* 0 step u64, 8 kind u8, 9 has_src u8, 10 src_lane u8, 11 cross u8
                                (StepFlags::CROSS), 16 src_lane_seq u64, 32 cut (u64 per lane) */
#define PBV_TX_BYTES    288u /* 0 step u64, 8 session u32, 12 resp_seq u32, 16 pkt_seq u32,
                                20 lane u8, 21 n_rec u8, 22 role u8, 23 n_rec x record[16]:
                                exactly the bytes H(tx) hashes */

/* Errors, in the in_tail / step_tail error word. Every one is final: the shell stops. */
#define PBV_E_MISMATCH    1u /* a record, route or response differs from what replay makes */
#define PBV_E_ORDER       2u /* REP_MERGE cannot order a lane call against a step */
#define PBV_E_SOURCE      3u /* a step's source op is missing or not forwarded */
#define PBV_E_KIND        4u /* a step's kind or number differs */
#define PBV_E_CUT         5u /* a cut moves back */
#define PBV_E_TOO_OLD     6u /* a call needs a step older than the client's history */
#define PBV_E_BAD_RECORD  7u /* a malformed record (a MID record first, too many MIDs) */
#define PBV_E_UNSUPPORTED 8u /* outside v1's subset, below */
#define PBV_E_FAULT       9u /* a ledger overflow, a capacity, an evicted snapshot or an
                                AcctTake that differs from the take replay makes */

/* v1 subset: New (Day, IOC, FOK, post-only), Cancel, Reduce, Heartbeat and ResendReq (no
 * LaneSeq, no response); SHED records (from the record alone, no payload, 05 §18 Q17); Cross, Improve, Shed,
 * Idle and Depletion steps. Replace, CancelAll, an STP that would trigger, in-packet
 * dependencies, Rescan, Control, Seal and Uncross steps, step payloads and snapshot/state bytes
 * stop with PBV_E_UNSUPPORTED. */

uint32_t pbv_abi_version(void);
uint64_t pbv_shared_bytes(uint32_t n_lanes);
/* Copies the tables. NULL when the config is malformed. mem outlives the context. */
pbv_ctx* pbv_new(const uint8_t* cfg, const uint8_t* accts, uint32_t n_accts,
                 const uint8_t* sess, uint32_t n_sess, void* mem);
void     pbv_lane_run(pbv_ctx* c, uint32_t lane); /* one thread per lane; returns on stop */
void     pbv_bbo_run(pbv_ctx* c);                 /* one thread; returns on stop */
int32_t  pbv_load_snapshot(pbv_ctx* c, const uint8_t* bytes, uint64_t len); /* v1: -PBV_E_UNSUPPORTED */
uint64_t pbv_state_bytes(pbv_ctx* c, uint8_t* out, uint64_t cap);          /* v1: 0 */
uint64_t pbv_siphash(uint64_t k0, uint64_t k1, const uint8_t* p, uint64_t n); /* golden check */
void     pbv_free(pbv_ctx* c); /* after every thread returned */

#endif /* VYRN_PBV_H */
