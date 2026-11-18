# Changelog of vyrn-wire

## vyrn-wire-v0.1.0 (2026-11-18)

- Scaffold the cargo workspace from spec/11-build.md §1 (5c29b3d)
- Implement vyrn-wire's packet and record codec (41dbb38)
- vyrn-wire: reject nonzero bytes 10-11 of the EpochNotice home word (ff1dbff)
- vyrn-wire: reject record indices outside 0-9 and 0xFF (8b055a3)
- vyrn-wire: RxRing/TxRing traits and NicCounters (06 §6.1) (a31c2cd)
- vyrn-wire: make RxPkt read-only and require backends to validate it in bytes() (2e97771)
- vyrn-wire: RxRing::bytes slices from the backend's own buffer, never RxPkt::data (dff3957)
- CDPI audit: reject vectors, golden README, version docs, pinned actions (b77680a)
- deploy/release: per-crate and final-package releases to GitHub Releases (39146b1)
- spec: settle Q13, Q14, CtlDone bytes and four oracle rulings (83b02fe)
- Bump PROTO_VERSION to 2 for the RATE_LIMIT id move (68681b9)

