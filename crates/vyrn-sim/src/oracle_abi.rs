//! The oracle's C structs (`vx/abi/pbv.h`), mirrored with the same sizes and offsets.

/// `PBO_ABI_VERSION`.
pub const ABI_VERSION: u32 = 1;
/// `pbo_apply` results other than a record count.
pub const E_CAP: u32 = u32::MAX;
/// A malformed event.
pub const E_EVENT: u32 = u32::MAX - 1;
/// The order table is full.
pub const E_FULL: u32 = u32::MAX - 2;
/// A balance overflowed after entry.
pub const E_FAULT: u32 = u32::MAX - 3;

/// `pbo_config`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub abi_version: u32,
    pub size: u32,
    pub band_lo: u32,
    pub band_hi: u32,
    pub quote_per_tick_lot: u64,
    pub max_fee_ppm: u32,
    pub min_qty: u32,
    pub max_order_qty: u32,
    pub max_open_per_acct: u32,
    pub max_orders: u32,
    pub phase: u8,
    pub reserved8: [u8; 3],
    pub reserved: [u32; 8],
    pub lane_rank: [u8; 64],
    pub lane_first_handle: [u32; 64],
}

/// `pbo_account`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Account {
    pub id: u32,
    pub lane: u8,
    pub reserved8: [u8; 3],
    pub maker_ppm: i32,
    pub taker_ppm: i32,
    pub auction_ppm: i32,
    pub reserved: u32,
    pub base_free: u64,
    pub quote_free: u64,
}

/// `pbo_session`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Session {
    pub session: u32,
    pub account: u32,
}

/// `pbo_event`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Event {
    pub kind: u8,
    pub lane: u8,
    pub index: u8,
    pub arg: u8,
    pub session: u32,
    pub pkt_seq: u32,
    pub reserved: u32,
    pub rx_ts: u64,
    pub step: u64,
    pub lane_seq: u64,
    pub msg: [u8; 16],
}

/// `pbo_record`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Record {
    pub session: u32,
    pub reserved: u32,
    pub step: u64,
    pub rec: [u8; 16],
}

const _: () = assert!(size_of::<Config>() == 400);
const _: () = assert!(core::mem::offset_of!(Config, lane_first_handle) == 144);
const _: () = assert!(size_of::<Account>() == 40);
const _: () = assert!(size_of::<Session>() == 8);
const _: () = assert!(size_of::<Event>() == 56);
const _: () = assert!(core::mem::offset_of!(Event, msg) == 40);
const _: () = assert!(size_of::<Record>() == 32);

impl Default for Config {
    fn default() -> Self {
        Self {
            abi_version: ABI_VERSION,
            size: 400,
            band_lo: 1,
            band_hi: u32::MAX,
            quote_per_tick_lot: 1,
            max_fee_ppm: 0,
            min_qty: 1,
            max_order_qty: (1 << 31) - 1,
            max_open_per_acct: 1_000,
            max_orders: 10_000,
            phase: 1,
            reserved8: [0; 3],
            reserved: [0; 8],
            lane_rank: core::array::from_fn(|l| l as u8),
            lane_first_handle: [(1 << 24) | 1; 64],
        }
    }
}
