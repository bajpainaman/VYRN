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
 * - Fees are ppm of notional (10 §5): ceil for a charge, floor for a rebate, once per fill. */

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
/* Client: vyrn-vx-client (11 §5.3). Not built yet.                                      */
/* ===================================================================================== */
typedef struct pbv_client pbv_client;

#endif /* VYRN_PBV_H */
