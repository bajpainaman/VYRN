//! Numeric codes: reject reasons (01 §6.5, §14.10, §14.19 C), step kinds (05 §8.1), homes and
//! modes (01 §1, §6.6).

/// An enum with an explicit wire code per variant, converted both ways without `as`.
macro_rules! coded {
    ($(#[$doc:meta])* $name:ident: $repr:ty { $($variant:ident = $code:literal,)+ }) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, core::hash::Hash)]
        #[repr($repr)]
        pub enum $name {
            $($variant = $code,)+
        }

        impl $name {
            /// Every variant, in code order.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            #[inline(always)]
            pub const fn code(self) -> $repr {
                match self {
                    $(Self::$variant => $code,)+
                }
            }

            #[inline(always)]
            pub const fn from_code(code: $repr) -> Option<Self> {
                match code {
                    $($code => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

coded!(
    /// `Reject.reason` (u16). 25 is reserved for `RESEND_RECOVERY` (03 Request 10), not yet in 01.
    RejectReason: u16 {
        BadMac = 1,
        BadSeq = 2,
        BadType = 3,
        BadTick = 4,
        BadQty = 5,
        RiskCredit = 6,
        RiskPosition = 7,
        RiskOrderCount = 8,
        RateLimit = 9,
        PostOnlyWouldCross = 10,
        FokUnfillable = 11,
        UnknownHandle = 12,
        TooLate = 13,
        BookHalted = 14,
        EpochMismatch = 15,
        Stp = 16,
        WrongLane = 17,
        SessionClosed = 18,
        AuctionPhase = 19,
        SideMismatch = 20,
        AccountKilled = 21,
        ResendGone = 22,
        BadBook = 23,
        Busy = 24,
        DataMissing = 26,
    }
);

coded!(
    /// `StepRecord.kind` (05 §8.1).
    StepKind: u8 {
        Cross = 1,
        Improve = 2,
        Rescan = 3,
        Depletion = 4,
        Idle = 5,
        Shed = 6,
        Control = 7,
        Seal = 8,
        Uncross = 9,
    }
);

coded!(
    /// The region that runs the active book (01 §6.6).
    HomeCode: u8 {
        Tyo = 1,
        Ldn = 2,
        Nyc = 3,
    }
);

/// Off-chain (n = 4) or on-chain (n = 5). The binaries are the same; the mode is configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, core::hash::Hash)]
pub enum Mode {
    Base,
    Chain,
}

impl Mode {
    /// Replica or validator set size: `N_BASE` or `N_CHAIN`.
    pub const fn n(self) -> usize {
        match self {
            Self::Base => crate::N_BASE,
            Self::Chain => crate::N_CHAIN,
        }
    }

    /// Quorum: `Q_BASE` or `Q_CHAIN` (`INV-QUORUM`).
    pub const fn quorum(self) -> usize {
        match self {
            Self::Base => crate::Q_BASE,
            Self::Chain => crate::Q_CHAIN,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_codes_match_01() {
        // Spot checks against 01 §6.5 and §14.10, both columns of the table.
        assert_eq!(RejectReason::BadMac.code(), 1);
        assert_eq!(RejectReason::FokUnfillable.code(), 11);
        assert_eq!(RejectReason::SideMismatch.code(), 20);
        assert_eq!(RejectReason::Busy.code(), 24);
        assert_eq!(RejectReason::DataMissing.code(), 26);
        assert_eq!(RejectReason::from_code(0), None);
        assert_eq!(RejectReason::from_code(25), None);
        assert_eq!(RejectReason::from_code(27), None);
        for r in RejectReason::ALL {
            assert_eq!(RejectReason::from_code(r.code()), Some(*r));
        }
        assert_eq!(RejectReason::ALL.len(), 25);
    }

    #[test]
    fn step_and_home_codes_round_trip() {
        for k in StepKind::ALL {
            assert_eq!(StepKind::from_code(k.code()), Some(*k));
        }
        assert_eq!(StepKind::Shed.code(), 6);
        assert_eq!(StepKind::from_code(10), None);
        assert_eq!(HomeCode::Ldn.code(), 2);
        assert_eq!(HomeCode::from_code(0), None);
    }

    #[test]
    fn quorums_tolerate_f() {
        for m in [Mode::Base, Mode::Chain] {
            // n − f signatures are needed, so f faulty voters can neither block nor forge.
            assert_eq!(m.quorum(), m.n() - crate::F);
        }
    }
}
