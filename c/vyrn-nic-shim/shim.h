/* The C ABI that vyrn-nic binds (spec/11-build.md §4, 06 §7.2). Prefix: vyns_. */
#ifndef VYRN_NIC_SHIM_H
#define VYRN_NIC_SHIM_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

/* ABI version; vyrn-nic refuses a shim that reports another (vyrn_wire::RING_ABI_VERSION). */
#define VYNS_ABI_VERSION   1u

#define VYNS_RX_TS         0x0001u  /* ts_ns is a NIC hardware timestamp */
#define VYNS_RX_TS_SYNC    0x0002u  /* the NIC clock reported "in sync"  */
#define VYNS_RX_BAD_CSUM   0x0004u
#define VYNS_RX_TRUNC      0x0008u

typedef struct vyns_rx {            /* 24 bytes; identical to vyrn_wire::RxPkt */
    const uint8_t *data;            /* first byte of the Ethernet frame      */
    uint16_t len;                   /* frame length without FCS              */
    uint16_t flags;                 /* VYNS_RX_*                             */
    uint32_t buf_id;
    uint64_t ts_ns;                 /* PHC time, TAI ns; 0 unless RX_TS      */
} vyns_rx;
_Static_assert(sizeof(vyns_rx) == 24 && offsetof(vyns_rx, ts_ns) == 16, "vyns_rx layout");

/* Single writer: the thread that polls the handle (relaxed load + store, never a locked RMW).
 * vyrn-nic's control thread reads them as AtomicU64 (vyrn_wire::NicCounters). */
typedef struct vyns_counters {
    _Atomic uint64_t rx_pkts, rx_discard, rx_no_ts, rx_trunc;
    _Atomic uint64_t tx_pkts, tx_ctpio, tx_fallback, tx_full;
    _Atomic uint64_t evq_overflow;  /* != 0: events were lost. Fatal.        */
    _Atomic uint64_t fatal_hw;      /* != 0: the device reported an error.   */
} vyns_counters;
_Static_assert(sizeof(vyns_counters) == 80, "vyns_counters layout");

uint32_t vyns_abi_version(void);

#endif /* VYRN_NIC_SHIM_H */
