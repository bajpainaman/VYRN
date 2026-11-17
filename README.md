<a href="https://www.vryn.trade"><img src="site/public/og.png" alt="A VYRN order ticket: filled within 1 µs of the first bit. Stamped filled ≤ 965 ns wire to wire, final in about 3 ms with 3 of 4 signed. One book at 1B msg/s, BFT final within 10 ms, home TYO → LDN → NYC, every figure a budget." width="100%"></a>

# VYRN

**Filled within 1 µs of the first bit.** One order book per instrument. 1B messages a second on that one book. BFT-final within 10 ms. A home that moves TYO → LDN → NYC every 8 hours. x86 and off-the-shelf NICs, no FPGA.

Every figure here is a design budget unless it says otherwise. No benchmark has run yet.

**[Website](https://www.vryn.trade)** · **[Read the design](https://www.vryn.trade/docs/design)** · **[Spec reader](https://www.vryn.trade/docs/00-index)** · **[Request a license](https://github.com/bajpainaman/VYRN/issues/new?template=license-request.yml)**

## How it fits together

<img src="site/public/diagrams/00-index-00.svg" alt="The master diagram. Clients send each packet twice: once to vyrn-seq in facility F1 (NICs, 49 lanes, cut core, BBO core, TX), and once to the vyrn-data tier. Fills and acks loop back to the clients within 1 µs. Order frames go on 2 paths and payloads go from the data tier to the vyrn-replica nodes, which replay the log and run Simplex. Their certificate gives finality within 10 ms. The finalized log goes over the WAN to the follower homes, and the book moves TYO to LDN to NYC every 8 hours, with each handoff a certificate plus an opening auction." width="100%">

Each packet is sent twice: one copy is ordered by the sequencer, the other feeds the data tier. Replicas join the two, replay the log and finalize it with Simplex.

### The sequencer box

<img src="site/public/diagrams/design-00.svg" alt="The sequencer box, top to bottom. Four 100GbE ports feed 49 lane cores, which parse, authenticate, check risk and keep the joins and cancels. Only improves and crosses go down to the BBO core. The cut core sends the cut and versioned BBO back up and feeds the BBO core. The BBO core, cut core and TX core share one CCD. Fills go through the fill ring to the TX core, then CTPIO to the wire, and ordering frames go twice to the replicas. Notes: a BBO step costs at most 15 ns, and the NIC is 560 of the 965 ns budget." width="100%">

Lanes keep joins and cancels; only improves and crosses reach the BBO core, at most 15 ns a step. The NIC takes 560 of the 965 ns budget.

The site renders every diagram in the spec; their sources are in [`site/diagrams/`](./site/diagrams).

## License and permitted use

VYRN is published under the **VYRN Research and Education License 1.0**. See [LICENSE](./LICENSE) for its complete terms.

**Free without prior permission:** noncommercial education, academic study, independent research, and experimentation or testing, provided the purpose is exclusively research or learning, and the user is not a restricted entity. You may study, run, modify, and redistribute the code for those permitted purposes subject to the license.

**Prior written permission required:** commercial or production use; use by or for **government bodies** or **financial institutions/businesses** (including banks, exchanges, trading firms, funds, brokers, market makers, and payment companies), even for research or testing; and any other use not expressly permitted.

### Request permission

[**Open a licensing request issue**](https://github.com/bajpainaman/VYRN/issues/new) and describe who you represent, your intended use, and whether it involves production or commercial activity.

**Opening an issue does not grant permission.** You must receive an express written license from the copyright holder before starting a restricted use.

This is **source-available**, not OSI-approved open source.

Copyright 2026 bajpainaman. If the actual rights holder is a company, the copyright notice and permissions process must be updated accordingly.

## Design and specification

- [DESIGN.md](./DESIGN.md): the design in one document.
- [spec/](./spec/00-index.md): the full specification, draft 0.2. Start at `00-index.md`; `01-conventions.md` is the contract every chapter follows.
